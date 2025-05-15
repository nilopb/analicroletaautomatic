from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import random

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # troque por uma chave secreta forte

DATABASE = 'roleta.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Cria tabela usuários
    cur.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        moedas INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    # Cria tabela palpites
    cur.execute('''
    CREATE TABLE IF NOT EXISTS palpites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        palpite TEXT,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    )
    ''')
    # Cria tabela apostas simuladas
    cur.execute('''
    CREATE TABLE IF NOT EXISTS apostas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        numeros TEXT,
        valor REAL,
        data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    )
    ''')
    conn.commit()
    conn.close()

init_db()

def enviar_alerta_admin(mensagem):
    # Aqui você pode configurar envio real (email, webhook, etc)
    print(f"ALERTA ADMIN: {mensagem}")

@app.route('/')
def index():
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_email = request.form['username_email']
        senha = request.form['senha']
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE username = ? OR email = ?", (username_email, username_email))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user['senha'], senha):
            session['usuario_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Login efetuado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        senha = request.form['senha']
        hashed_password = generate_password_hash(senha)
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO usuarios (username, email, senha) VALUES (?, ?, ?)", (username, email, hashed_password))
            conn.commit()
            enviar_alerta_admin(f"Novo usuário cadastrado: {username} ({email})")
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário ou e-mail já cadastrado.', 'danger')
        finally:
            conn.close()
    return render_template('registro.html')

def pegar_ultimos_resultados():
    # Função para simular pegar últimos 100 resultados da roleta (0-36)
    # Substitua pelo scraping ou API real no futuro
    return [random.randint(0, 36) for _ in range(100)]

def gerar_palpites(ultimos_resultados):
    # Exemplo simples de predição: pega os 5 números mais frequentes nos últimos 100 resultados
    series = pd.Series(ultimos_resultados)
    frequencias = series.value_counts().head(5).index.tolist()
    return frequencias

@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    ultimos_resultados = pegar_ultimos_resultados()
    palpites = gerar_palpites(ultimos_resultados)
    # Guardar palpites no banco (opcional)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO palpites (usuario_id, palpite) VALUES (?, ?)", (session['usuario_id'], ','.join(map(str, palpites))))
    conn.commit()
    conn.close()
    return render_template('dashboard.html', palpites=palpites, ultimos_resultados=ultimos_resultados, username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da conta.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'is_admin' not in session or not session['is_admin']:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, moedas FROM usuarios")
    usuarios = cur.fetchall()
    conn.close()
    return render_template('admin.html', usuarios=usuarios)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'is_admin' not in session or not session['is_admin']:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('Usuário deletado.', 'success')
    return redirect(url_for('admin'))

@app.route('/simulacao_apostas', methods=['GET', 'POST'])
def simulacao_apostas():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        numeros = request.form.getlist('numeros')  # lista de números apostados
        valor = float(request.form['valor'])
        # Aqui você pode validar limites para modo responsável
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO apostas (usuario_id, numeros, valor) VALUES (?, ?, ?)", (session['usuario_id'], ','.join(numeros), valor))
        conn.commit()
        conn.close()
        flash('Aposta simulada com sucesso!', 'success')
        return redirect(url_for('simulacao_apostas'))
    return render_template('simulacao_apostas.html')

@app.route('/iframe_roleta')
def iframe_roleta():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    return render_template('iframe_roleta.html')

if __name__ == '__main__':
    app.run(debug=True)
import random

# Função para simular coleta dos últimos 100 números da roleta
def get_ultimos_numeros():
    # Aqui você deve fazer scraping ou API real, mas vamos simular
    return [random.randint(0, 36) for _ in range(100)]

# Função simples que gera os 5 números mais frequentes nos últimos 100
def gerar_palpites():
    ultimos = get_ultimos_numeros()
    freq = {}
    for num in ultimos:
        freq[num] = freq.get(num, 0) + 1
    palpites = sorted(freq, key=freq.get, reverse=True)[:5]
    return palpites, ultimos

@app.route('/palpites')
@login_required
def palpites():
    palpites, ultimos = gerar_palpites()
    return render_template('palpites.html', palpites=palpites, ultimos=ultimos)
