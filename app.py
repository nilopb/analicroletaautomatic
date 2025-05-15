# app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests
import re

app = Flask(__name__)
app.secret_key = 'seu_secret_key_aqui'  # troque para algo seguro

DATABASE = 'database.db'


# --- UTILITÁRIOS BANCO DE DADOS ---

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    # tabela usuários
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    # tabela apostas
    c.execute('''
        CREATE TABLE IF NOT EXISTS apostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            numeros TEXT,
            valor REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()


# --- ROTA PRINCIPAL - LOGIN ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('usuario'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Login realizado com sucesso!', 'success')
            if user['is_admin']:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('usuario'))
        else:
            flash('Usuário ou senha inválidos', 'error')

    return render_template('login.html')


# --- ROTA CADASTRO ---

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('As senhas não coincidem.', 'error')
            return render_template('registro.html')

        if not re.match(r'^[\w.@+-]+$', username):
            flash('Nome de usuário inválido. Use apenas letras, números e @/./+/-/_', 'error')
            return render_template('registro.html')

        hashed_password = generate_password_hash(password, method='sha256')

        try:
            conn = get_db()
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()
            conn.close()

            # Alerta para admin - aqui só print (pode evoluir para email)
            print(f'Novo usuário cadastrado: {username} - {email}')

            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário ou email já cadastrados.', 'error')

    return render_template('registro.html')


# --- ROTA USUÁRIO (Área principal) ---

@app.route('/usuario')
def usuario():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Dados simulados palpites (pode trocar pela lógica real depois)
    palpites = gerar_palpites()

    return render_template('usuario.html', username=session['username'], palpites=palpites)


def gerar_palpites():
    # Exemplo: gera 5 números aleatórios entre 0-36 (roleta europeia)
    import random
    return sorted(random.sample(range(37), 5))


# --- ROTA ADMIN ---

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Acesso negado.', 'error')
        return redirect(url_for('login'))

    conn = get_db()
    users = conn.execute('SELECT id, username, email FROM users WHERE is_admin=0').fetchall()
    conn.close()
    return render_template('admin.html', users=users)


# --- ROTA LOGOUT ---

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da conta.', 'success')
    return redirect(url_for('login'))


# --- INICIALIZAÇÃO DO BANCO ---

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 
