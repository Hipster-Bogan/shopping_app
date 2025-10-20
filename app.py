import errno
import time

import eventlet

# Avoid monkey patching the ``os`` module because Gunicorn's eventlet worker
# writes to an internal pipe while processing signals.  Eventlet's green
# ``os.write`` implementation attempts to yield control using the hub
# trampoline, which raises ``RuntimeError: do not call blocking functions from
# the mainloop`` under Python 3.13.  Leaving ``os`` untouched prevents the
# trampoline from being invoked in this context while keeping the rest of the
# cooperative patches that Flask-SocketIO needs.
eventlet.monkey_patch(os=False)

# Gunicorn's Eventlet worker occasionally attempts to shutdown client
# sockets that have already been closed by the remote peer.  In that
# situation Eventlet's ``GreenSocket`` forwards the call to the real
# socket object, which raises ``EBADF`` and produces noisy log entries
# such as ``socket shutdown error: [Errno 9] Bad file descriptor``.
#
# Monkey-patching the GreenSocket initialiser lets us wrap the
# underlying ``shutdown`` method and quietly ignore ``EBADF`` (and the
# related ``ENOTCONN``) while preserving the default behaviour for every
# other error.
import socket

try:  # pragma: no cover - import path depends on Eventlet version
    from eventlet.greenio.base import GreenSocket as _EventletGreenSocket
except ImportError:  # pragma: no cover - Eventlet <0.34 exposes GreenSocket at package level
    try:
        from eventlet.greenio import GreenSocket as _EventletGreenSocket
    except ImportError:  # pragma: no cover - fail gracefully if structure changes
        _EventletGreenSocket = None

if _EventletGreenSocket is not None and not getattr(
    _EventletGreenSocket, "_safe_shutdown_wrapped", False
):
    _original_greensocket_init = _EventletGreenSocket.__init__

    def _safe_shutdown_greensocket_init(self, *args, **kwargs):
        _original_greensocket_init(self, *args, **kwargs)
        real_shutdown = getattr(self, "shutdown", None)

        if real_shutdown is None:
            return

        def _shutdown_wrapper(how=socket.SHUT_RDWR):
            try:
                return real_shutdown(how)
            except OSError as exc:  # pragma: no cover - defensive guard
                if exc.errno in (errno.EBADF, errno.ENOTCONN):
                    return None
                raise

        self.shutdown = _shutdown_wrapper

    _EventletGreenSocket.__init__ = _safe_shutdown_greensocket_init
    _EventletGreenSocket._safe_shutdown_wrapped = True

import os
import re
import secrets
import string
from pathlib import Path
from types import SimpleNamespace

from functools import wraps

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    g,
)
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import (Boolean, Column, ForeignKey, Integer, MetaData, String,
                        Table, create_engine, delete, insert, select, update, inspect, text)
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

DEFAULT_SQLITE_FILENAME = "shopping.db"


def _resolve_sqlite_url(filename: str) -> str:
    """Return a SQLite connection URL, ensuring the directory exists."""

    custom_file = os.environ.get("DATABASE_FILE")
    if custom_file:
        db_path = Path(custom_file).expanduser()
    else:
        base_dir = os.environ.get("APP_STATE_DIR") or os.environ.get("DATA_DIR")
        if base_dir:
            db_path = Path(base_dir).expanduser() / filename
        else:
            db_path = Path(__file__).resolve().parent / filename

    if not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    return f"sqlite:///{db_path}"


DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL:
    if DATABASE_URL.startswith("sqlite:///"):
        sqlite_path = DATABASE_URL.replace("sqlite:///", "", 1)
        if sqlite_path.startswith(os.sep):
            sqlite_url = DATABASE_URL
        else:
            sqlite_url = _resolve_sqlite_url(sqlite_path)
        engine = create_engine(
            sqlite_url,
            connect_args={"check_same_thread": False},
            future=True,
        )
    else:
        engine = create_engine(DATABASE_URL, future=True)
else:
    engine = create_engine(
        _resolve_sqlite_url(DEFAULT_SQLITE_FILENAME),
        connect_args={"check_same_thread": False},
        future=True,
    )

metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("is_admin", Boolean, nullable=False, default=False),
    Column("is_approved", Boolean, nullable=False, default=False),
)

lists_table = Table(
    "lists",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("token", String(32), unique=True, nullable=False),
)

list_items_table = Table(
    "list_items",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("list_id", Integer, ForeignKey("lists.id"), nullable=False),
    Column("item", String(255), nullable=False),
    Column("quantity", Integer, nullable=False, default=1),
    Column("checked", Boolean, nullable=False, default=False),
)

metadata.create_all(engine)


def ensure_schema():
    dialect = engine.dialect.name
    false_literal = "0" if dialect == "sqlite" else "FALSE"
    true_literal = "1" if dialect == "sqlite" else "TRUE"

    with engine.begin() as conn:
        inspector = inspect(conn)
        columns = {col["name"] for col in inspector.get_columns("users")}

        if "is_admin" not in columns:
            conn.execute(
                text(
                    f"ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT {false_literal}"
                )
            )

        if "is_approved" not in columns:
            conn.execute(
                text(
                    f"ALTER TABLE users ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT {false_literal}"
                )
            )
            conn.execute(text(f"UPDATE users SET is_approved = {true_literal}"))

    with engine.begin() as conn:
        conn.execute(
            update(users_table)
            .where(users_table.c.is_admin.is_(None))
            .values(is_admin=False)
        )
        conn.execute(
            update(users_table)
            .where(users_table.c.is_approved.is_(None))
            .values(is_approved=True)
        )


def ensure_initial_admin():
    with engine.begin() as conn:
        admin_exists = conn.execute(
            select(users_table.c.id).where(users_table.c.is_admin.is_(True))
        ).first()
        if admin_exists:
            return

        first_user = conn.execute(
            select(users_table.c.id).order_by(users_table.c.id)
        ).first()

        if first_user:
            conn.execute(
                update(users_table)
                .where(users_table.c.id == first_user[0])
                .values(is_admin=True, is_approved=True)
            )


def _initialise_database_with_retry(max_attempts=5, initial_delay=1.0, max_delay=30.0):
    """Ensure the database schema exists, retrying if the database is waking up."""

    delay = initial_delay
    attempt = 1

    while True:
        try:
            ensure_schema()
            ensure_initial_admin()
            return
        except OperationalError as exc:
            if attempt >= max_attempts:
                raise

            print(
                "Database initialisation failed (attempt {} of {}): {}. Retrying in {:.1f}s".format(
                    attempt, max_attempts, exc, delay
                )
            )
            time.sleep(delay)
            delay = min(delay * 2, max_delay)
            attempt += 1


_initialise_database_with_retry()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "BirdwoodHeights(#)")
socketio = SocketIO(app, cors_allowed_origins="*")  # restrict in production

# ---- Helpers ----
def gen_token(length=6):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_list_record(raw_name):
    """Create a shopping list row and return its share token."""

    name = (raw_name or "").strip()
    if not name:
        raise ValueError("List name required")

    while True:
        token = gen_token()
        try:
            with engine.begin() as conn:
                conn.execute(insert(lists_table).values(name=name, token=token))
            return token
        except IntegrityError:
            # Token collision is unlikely but retry on the off-chance it happens.
            continue


def valid_item_text(s):
    # basic validation to avoid massive input or control chars
    if not s or len(s) > 200:
        return False
    # allow letters, numbers, punctuation, spaces
    return bool(re.match(r'^[\w\s\-\.,!()&/]+$', s))


def load_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with engine.connect() as conn:
        user = conn.execute(
            select(users_table).where(users_table.c.id == user_id)
        ).mappings().first()

    return user


def require_current_user(require_admin=False):
    user = load_current_user()
    if not user:
        session.clear()
        return None, redirect(url_for("login"))

    if not user["is_approved"]:
        session.clear()
        return None, redirect(url_for("login", msg="not_approved"))

    session["email"] = user["email"]
    session["is_admin"] = bool(user["is_admin"])

    if require_admin and not user["is_admin"]:
        return None, redirect(url_for("home"))

    return user, None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user, response = require_current_user()
        if response is not None:
            return response
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user, response = require_current_user(require_admin=True)
        if response is not None:
            return response
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper

# ---- Auth routes ----
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    error = None
    if request.method == 'POST':
        try:
            create_list_record(request.form.get('list_name'))
            return redirect(url_for('home'))
        except ValueError:
            error = "Please enter a name for your list."

    with engine.connect() as conn:
        result = conn.execute(select(lists_table).order_by(lists_table.c.id.desc()))
        lists = [dict(row._mapping) for row in result]

    return render_template('create_list.html', lists=lists, error=error)



@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if not email or not password:
            error = "Please provide both email and password."
        elif len(password) < 8:
            error = "Password must be at least 8 characters long."
        else:
            pw_hash = generate_password_hash(password)
            try:
                with engine.begin() as conn:
                    is_first_user = conn.execute(
                        select(users_table.c.id).limit(1)
                    ).first() is None

                    conn.execute(
                        insert(users_table).values(
                            email=email,
                            password_hash=pw_hash,
                            is_admin=is_first_user,
                            is_approved=is_first_user,
                        )
                    )
            except IntegrityError:
                error = "A user with that email already exists."
            else:
                if is_first_user:
                    return redirect(url_for('login', msg='first_admin'))
                return redirect(url_for('login', msg='pending'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET','POST'])
def login():
    message = None
    msg_code = request.args.get('msg')
    if msg_code == 'pending':
        message = "Account created. Please wait for an administrator to approve your access."
    elif msg_code == 'first_admin':
        message = "Administrator account created. You can now sign in."
    elif msg_code == 'not_approved':
        message = "Your account is not approved yet. Contact an administrator for assistance."
    elif msg_code == 'password_reset':
        message = "Password updated. Please sign in with your new password."

    error = None
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        with engine.connect() as conn:
            user = conn.execute(
                select(users_table).where(users_table.c.email == email)
            ).mappings().first()
        if not user or not check_password_hash(user['password_hash'], password):
            error = "Invalid credentials."
        elif not user['is_approved']:
            error = "Your account is awaiting approval."
        else:
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('home'))
    return render_template('login.html', error=error, message=message)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---- List management ----
@app.route('/create_list', methods=['POST'])
@login_required
def create_list():
    raw_name = request.form.get('list_name') or request.form.get('name')
    try:
        token = create_list_record(raw_name)
    except ValueError:
        return "List name required", 400
    return redirect(url_for('open_list', token=token))

@app.route('/admin/users', methods=['GET','POST'])
@admin_required
def manage_users():
    message = None
    error = None

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            target_id = int(request.form.get('user_id', '0'))
        except (TypeError, ValueError):
            target_id = 0
        current_user = g.current_user

        if not target_id:
            error = "Invalid user identifier."

        if error is None:
            with engine.begin() as conn:
                target = conn.execute(
                    select(users_table).where(users_table.c.id == target_id)
                ).mappings().first()

                if not target:
                    error = "User not found."
                else:
                    if action == 'approve':
                        if target['is_approved']:
                            message = f"{target['email']} is already approved."
                        else:
                            conn.execute(
                                update(users_table)
                                .where(users_table.c.id == target_id)
                                .values(is_approved=True)
                            )
                            message = f"Approved access for {target['email']}."
                    elif action == 'deactivate':
                        if target_id == current_user['id'] and target['is_admin']:
                            error = "You cannot deactivate your own administrator account."
                        else:
                            if target['is_admin']:
                                other_admin = conn.execute(
                                    select(users_table.c.id)
                                    .where(
                                        users_table.c.is_admin.is_(True),
                                        users_table.c.id != target_id,
                                    )
                                    .limit(1)
                                ).first()
                                if not other_admin:
                                    error = "Cannot deactivate the last administrator."
                            if error is None:
                                conn.execute(
                                    update(users_table)
                                    .where(users_table.c.id == target_id)
                                    .values(is_approved=False)
                                )
                                message = f"Deactivated {target['email']}."
                    elif action == 'make_admin':
                        if target['is_admin']:
                            message = f"{target['email']} is already an administrator."
                        else:
                            conn.execute(
                                update(users_table)
                                .where(users_table.c.id == target_id)
                                .values(is_admin=True, is_approved=True)
                            )
                            message = f"Granted administrator rights to {target['email']}."
                    elif action == 'remove_admin':
                        if not target['is_admin']:
                            message = f"{target['email']} is not an administrator."
                        else:
                            other_admin = conn.execute(
                                select(users_table.c.id)
                                .where(
                                    users_table.c.is_admin.is_(True),
                                    users_table.c.id != target_id,
                                )
                                .limit(1)
                            ).first()
                            if not other_admin:
                                error = "Cannot remove the last administrator."
                            else:
                                conn.execute(
                                    update(users_table)
                                    .where(users_table.c.id == target_id)
                                    .values(is_admin=False)
                                )
                                message = f"Removed administrator rights from {target['email']}."
                    elif action == 'reset_password':
                        new_password = (request.form.get('new_password') or '').strip()
                        if len(new_password) < 8:
                            error = "New password must be at least 8 characters long."
                        else:
                            pw_hash = generate_password_hash(new_password)
                            conn.execute(
                                update(users_table)
                                .where(users_table.c.id == target_id)
                                .values(password_hash=pw_hash)
                            )
                            message = f"Password updated for {target['email']}."
                    else:
                        error = "Unsupported action."

        if error is None and target_id == current_user['id']:
            updated_user = load_current_user()
            if updated_user:
                session['is_admin'] = bool(updated_user['is_admin'])

    with engine.connect() as conn:
        users = conn.execute(
            select(users_table).order_by(users_table.c.id)
        ).mappings().all()

    return render_template(
        'admin_users.html',
        users=users,
        message=message,
        error=error,
        current_user_id=g.current_user['id'],
    )


@app.route('/account/password', methods=['GET', 'POST'])
@login_required
def change_password():
    message = None
    error = None
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not new_password or len(new_password) < 8:
            error = "New password must be at least 8 characters long."
        elif new_password != confirm_password:
            error = "New password and confirmation do not match."
        elif not check_password_hash(g.current_user['password_hash'], current_password):
            error = "Current password is incorrect."
        else:
            pw_hash = generate_password_hash(new_password)
            with engine.begin() as conn:
                conn.execute(
                    update(users_table)
                    .where(users_table.c.id == g.current_user['id'])
                    .values(password_hash=pw_hash)
                )
            message = "Password updated successfully."
            g.current_user['password_hash'] = pw_hash

    return render_template('account.html', message=message, error=error)


@app.route('/join', methods=['GET','POST'])
def join():
    if request.method == 'POST':
        token = request.form.get('token', '').strip().upper()
        return redirect(url_for('open_list', token=token))
    return render_template('create_list.html', join_mode=True, error=None, lists=None)

@app.route('/list/<token>')
def open_list(token):
    token = token.strip().upper()
    with engine.connect() as conn:
        lst = conn.execute(
            select(lists_table).where(lists_table.c.token == token)
        ).mappings().first()
        if not lst:
            return "List not found", 404
        rows = conn.execute(
            select(list_items_table)
            .where(list_items_table.c.list_id == lst['id'])
            .order_by(list_items_table.c.id)
        ).mappings().all()

    items = [
        SimpleNamespace(
            id=row['id'],
            item=row['item'],
            quantity=row['quantity'],
            checked=bool(row['checked']),
        )
        for row in rows
    ]

    shopping_list = SimpleNamespace(
        id=lst['id'],
        name=lst['name'],
        token=token,
        share_token=token,
        share_url=url_for('open_list', token=token, _external=True),
        items=items,
    )

    return render_template('list.html', shopping_list=shopping_list)

@app.route('/api/list/<token>/items', methods=['GET'])
def api_list_items(token):
    token = token.strip().upper()
    with engine.connect() as conn:
        lst_id = conn.execute(
            select(lists_table.c.id).where(lists_table.c.token == token)
        ).scalar_one_or_none()
        if not lst_id:
            return jsonify({"error": "not found"}), 404
        items = conn.execute(
            select(list_items_table).where(list_items_table.c.list_id == lst_id)
        ).mappings().all()
    result = [
        dict(
            id=row['id'],
            item=row['item'],
            quantity=row['quantity'],
            checked=bool(row['checked']),
        )
        for row in items
    ]
    return jsonify(result)

# ---- Socket events ----
@socketio.on('join')
def on_join(data):
    token = data.get('token','').strip().upper()
    name = data.get('name','Guest')[:50]
    with engine.connect() as conn:
        lst_id = conn.execute(
            select(lists_table.c.id).where(lists_table.c.token == token)
        ).scalar_one_or_none()
    if not lst_id:
        emit('error', {'msg': 'List not found'})
        return
    room = f"list_{token}"
    join_room(room)
    emit('status', {'msg': f'{name} joined'}, room=room)

@socketio.on('add_item')
def on_add_item(data):
    token = data.get('token','').strip().upper()
    item_text = data.get('item','').strip()
    quantity = int(data.get('quantity', 1))
    if not valid_item_text(item_text) or quantity < 1 or quantity > 999:
        emit('error', {'msg':'Invalid item'})
        return
    with engine.begin() as conn:
        lst_id = conn.execute(
            select(lists_table.c.id).where(lists_table.c.token == token)
        ).scalar_one_or_none()
        if not lst_id:
            emit('error', {'msg':'List not found'})
            return
        result = conn.execute(
            insert(list_items_table).values(
                list_id=lst_id, item=item_text, quantity=quantity
            )
        )
        item_id = result.inserted_primary_key[0]
    item = {'id': item_id, 'item': item_text, 'quantity': quantity, 'checked': False}
    room = f"list_{token}"
    emit('item_added', item, room=room)

@socketio.on('toggle_item')
def on_toggle_item(data):
    token = data.get('token','').strip().upper()
    item_id = int(data.get('id', 0))
    with engine.begin() as conn:
        lst_id = conn.execute(
            select(lists_table.c.id).where(lists_table.c.token == token)
        ).scalar_one_or_none()
        if not lst_id:
            emit('error', {'msg':'List not found'})
            return
        row = conn.execute(
            select(list_items_table.c.checked).where(
                (list_items_table.c.id == item_id)
                & (list_items_table.c.list_id == lst_id)
            )
        ).scalar_one_or_none()
        if row is None:
            emit('error', {'msg':'Item not found'})
            return
        new_checked = not bool(row)
        conn.execute(
            update(list_items_table)
            .where(
                (list_items_table.c.id == item_id)
                & (list_items_table.c.list_id == lst_id)
            )
            .values(checked=new_checked)
        )
    room = f"list_{token}"
    emit('item_toggled', {'id': item_id, 'checked': bool(new_checked)}, room=room)

@socketio.on('delete_item')
def on_delete_item(data):
    token = data.get('token','').strip().upper()
    item_id = int(data.get('id',0))
    with engine.begin() as conn:
        lst_id = conn.execute(
            select(lists_table.c.id).where(lists_table.c.token == token)
        ).scalar_one_or_none()
        if not lst_id:
            emit('error', {'msg':'List not found'})
            return
        conn.execute(
            delete(list_items_table)
            .where(
                (list_items_table.c.id == item_id)
                & (list_items_table.c.list_id == lst_id)
            )
        )
    room = f"list_{token}"
    emit('item_deleted', {'id': item_id}, room=room)

# ---- Run ----
if __name__ == '__main__':
    # For dev: socketio.run(app, debug=True)
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
