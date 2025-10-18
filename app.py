from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'replace_this_with_a_secure_random_key'
DB = 'shopping.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS shopping_list (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        item TEXT,
        quantity INTEGER DEFAULT 1,
        checked BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

init_db()

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('shopping_list'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hash_pw = generate_password_hash(password)
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hash_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except:
            return "User already exists"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['email'] = user['email']
            return redirect(url_for('shopping_list'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/shopping_list', methods=['GET', 'POST'])
def shopping_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    if request.method == 'POST':
        item = request.form['item']
        quantity = int(request.form.get('quantity', 1))
        conn.execute("INSERT INTO shopping_list (user_id, item, quantity) VALUES (?, ?, ?)",
                     (session['user_id'], item, quantity))
        conn.commit()

    items = conn.execute("SELECT * FROM shopping_list WHERE user_id=?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('list.html', items=items)

@app.route('/toggle/<int:item_id>')
def toggle(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    item = conn.execute("SELECT checked FROM shopping_list WHERE id=? AND user_id=?", (item_id, session['user_id'])).fetchone()
    if item:
        conn.execute("UPDATE shopping_list SET checked=? WHERE id=?",
                     (0 if item['checked'] else 1, item_id))
        conn.commit()
    conn.close()
    return redirect(url_for('shopping_list'))

@app.route('/delete/<int:item_id>')
def delete(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    conn.execute("DELETE FROM shopping_list WHERE id=? AND user_id=?", (item_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('shopping_list'))

if __name__ == '__main__':
    app.run(debug=True)
