import eventlet
eventlet.monkey_patch()

import sqlite3
import secrets
import string
from types import SimpleNamespace
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, leave_room, emit
import re
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
import os

DB_PATH = "shopping.db"

def get_db_connection():
    conn = sqlite3.connect('shopping.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "BirdwoodHeights(#)")
socketio = SocketIO(app, cors_allowed_origins="*")  # restrict in production

DB = 'shopping.db'

def get_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        token TEXT UNIQUE
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS list_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        list_id INTEGER,
        item TEXT,
        quantity INTEGER DEFAULT 1,
        checked INTEGER DEFAULT 0,
        FOREIGN KEY (list_id) REFERENCES lists(id)
    )""")
    conn.commit()
    conn.close()

init_db()

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
            conn = get_db()
            conn.execute('INSERT INTO lists (name, token) VALUES (?, ?)', (list_name, token))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))

    conn = get_db()
    lists = conn.execute('SELECT * FROM lists ORDER BY id DESC').fetchall()
    conn.close()

    return render_template('create_list.html', lists=lists)



@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if not email or not password:
            return "Missing fields", 400
        pw_hash = generate_password_hash(password)
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return "User exists", 400
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
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
    conn = get_db()
    conn.execute("INSERT INTO lists (name, token) VALUES (?, ?)", (name, token))
    conn.commit()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    conn.close()
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
    conn = get_db()
    lst = conn.execute("SELECT * FROM lists WHERE token=?", (token,)).fetchone()
    if not lst:
        return "List not found", 404
    # fetch items
    rows = conn.execute(
        "SELECT * FROM list_items WHERE list_id=? ORDER BY id",
        (lst['id'],),
    ).fetchall()
    conn.close()

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
        items=items,
    )

    return render_template('list.html', shopping_list=shopping_list)

@app.route('/api/list/<token>/items', methods=['GET'])
def api_list_items(token):
    token = token.strip().upper()
    conn = get_db()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    if not lst:
        return jsonify({"error":"not found"}), 404
    items = conn.execute("SELECT * FROM list_items WHERE list_id=?", (lst['id'],)).fetchall()
    result = [dict(id=row['id'], item=row['item'], quantity=row['quantity'], checked=bool(row['checked'])) for row in items]
    return jsonify(result)

# ---- Socket events ----
@socketio.on('join')
def on_join(data):
    token = data.get('token','').strip().upper()
    name = data.get('name','Guest')[:50]
    conn = get_db()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    conn.close()
    if not lst:
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
    conn = get_db()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    if not lst:
        conn.close()
        emit('error', {'msg':'List not found'})
        return
    res = conn.execute("INSERT INTO list_items (list_id, item, quantity) VALUES (?, ?, ?)", (lst['id'], item_text, quantity))
    conn.commit()
    item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()['id']
    item = {'id': item_id, 'item': item_text, 'quantity': quantity, 'checked': False}
    conn.close()
    room = f"list_{token}"
    emit('item_added', item, room=room)

@socketio.on('toggle_item')
def on_toggle_item(data):
    token = data.get('token','').strip().upper()
    item_id = int(data.get('id', 0))
    conn = get_db()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    if not lst:
        conn.close()
        emit('error', {'msg':'List not found'})
        return
    row = conn.execute("SELECT checked FROM list_items WHERE id=? AND list_id=?", (item_id, lst['id'])).fetchone()
    if not row:
        conn.close()
        emit('error', {'msg':'Item not found'})
        return
    new_checked = 0 if row['checked'] else 1
    conn.execute("UPDATE list_items SET checked=? WHERE id=?", (new_checked, item_id))
    conn.commit()
    conn.close()
    room = f"list_{token}"
    emit('item_toggled', {'id': item_id, 'checked': bool(new_checked)}, room=room)

@socketio.on('delete_item')
def on_delete_item(data):
    token = data.get('token','').strip().upper()
    item_id = int(data.get('id',0))
    conn = get_db()
    lst = conn.execute("SELECT id FROM lists WHERE token=?", (token,)).fetchone()
    if not lst:
        conn.close()
        emit('error', {'msg':'List not found'})
        return
    conn.execute("DELETE FROM list_items WHERE id=? AND list_id=?", (item_id, lst['id']))
    conn.commit()
    conn.close()
    room = f"list_{token}"
    emit('item_deleted', {'id': item_id}, room=room)

# ---- Run ----
if __name__ == '__main__':
    # For dev: socketio.run(app, debug=True)
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
