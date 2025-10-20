import errno

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
from types import SimpleNamespace

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import (Boolean, Column, ForeignKey, Integer, MetaData, String,
                        Table, create_engine, delete, insert, select, update)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = "shopping.db"

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL:
    engine = create_engine(DATABASE_URL, future=True)
else:
    engine = create_engine(
        f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False}, future=True
    )

metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
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

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "BirdwoodHeights(#)")
socketio = SocketIO(app, cors_allowed_origins="*")  # restrict in production

# ---- Helpers ----
def gen_token(length=6):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def valid_item_text(s):
    # basic validation to avoid massive input or control chars
    if not s or len(s) > 200:
        return False
    # allow letters, numbers, punctuation, spaces
    return bool(re.match(r'^[\w\s\-\.,!()&/]+$', s))

# ---- Auth routes ----
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        list_name = request.form.get('list_name')
        if list_name:
            token = gen_token()
            with engine.begin() as conn:
                conn.execute(
                    insert(lists_table).values(name=list_name.strip(), token=token)
                )
            return redirect(url_for('home'))

    with engine.connect() as conn:
        result = conn.execute(select(lists_table).order_by(lists_table.c.id.desc()))
        lists = [dict(row._mapping) for row in result]

    return render_template('create_list.html', lists=lists)



@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if not email or not password:
            return "Missing fields", 400
        pw_hash = generate_password_hash(password)
        try:
            with engine.begin() as conn:
                conn.execute(
                    insert(users_table).values(email=email, password_hash=pw_hash)
                )
        except IntegrityError:
            return "User exists", 400
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        with engine.connect() as conn:
            user = conn.execute(
                select(users_table).where(users_table.c.email == email)
            ).mappings().first()
        if not user or not check_password_hash(user['password_hash'], password):
            return "Invalid credentials", 401
        session['user_id'] = user['id']
        session['email'] = user['email']
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---- List management ----
@app.route('/create_list', methods=['POST'])
def create_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    name = request.form.get('name', 'Shopping List').strip()
    token = gen_token()
    with engine.begin() as conn:
        conn.execute(insert(lists_table).values(name=name, token=token))
    return redirect(url_for('open_list', token=token))

@app.route('/join', methods=['GET','POST'])
def join():
    if request.method == 'POST':
        token = request.form.get('token', '').strip().upper()
        return redirect(url_for('open_list', token=token))
    return render_template('create_list.html', join_mode=True)

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
