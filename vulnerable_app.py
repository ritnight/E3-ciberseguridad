from flask import Flask, request, render_template_string, session, redirect, url_for, flash
import os
import hashlib
import mysql.connector

app = Flask(__name__)

# MITIGACIÓN: Secret Key segura desde variables de entorno
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

def get_db_connection():
    # MITIGACIÓN: Credenciales extraídas de variables de entorno (No hardcoded)
    db_config = {
        'host': os.environ.get('DB_HOST', 'localhost'),
        'user': os.environ.get('DB_USER', 'root'),
        'password': os.environ.get('DB_PASSWORD', ''), # Lee la password del sistema o usa vacía
        'database': os.environ.get('DB_NAME', 'prueba')
    }
    conn = mysql.connector.connect(**db_config)
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor() # Usamos cursor estándar para acceder por índices [0]

        # MITIGACIÓN CRÍTICA: Se eliminó el IF que permitía inyección SQL.
        # Ahora SIEMPRE se usa consulta parametrizada.
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        hashed_password = hash_password(password)

        try:
            # Los parámetros van en una tupla, separados de la query
            cursor.execute(query, (username, hashed_password))
            user = cursor.fetchone()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            user = None
        finally:
            cursor.close()
            conn.close()

        if user:
            # Asumiendo que la tabla users es: id (0), username (1), password (2), role (3)
            session['user_id'] = user[0]
            # Verificamos si existe la columna rol, si no, asignamos 'user' por defecto
            session['role'] = user[3] if len(user) > 3 else 'user'
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials!'
            
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    # Usamos dictionary cursor aquí para facilitar el uso en el template (task['task'])
    cur = conn.cursor(dictionary=True) 
    
    cur.execute("SELECT * FROM tasks WHERE user_id = %s", (user_id,))
    tasks = cur.fetchall() 
    cur.close()
    conn.close()

    return render_template_string('''
        <h1>Welcome, user {{ user_id }}!</h1>
        <form action="/add_task" method="post">
            <input type="text" name="task" placeholder="New task"><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            {# Asegúrate que tu tabla tasks tenga columnas 'id' y 'task' #}
            <li>{{ task['tasks'] }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
        {% endfor %}
        </ul>
    ''', user_id=user_id, tasks=tasks)

@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task_content = request.form['task']
    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()
    # MITIGACIÓN: Consulta parametrizada para INSERT
    cur.execute("INSERT INTO tasks (user_id, tasks) VALUES (%s, %s)", (user_id, task_content))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    # MITIGACIÓN: Consulta parametrizada para DELETE
    cur.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return 'Welcome to the admin panel!'

if __name__ == '__main__':
    # MITIGACIÓN: Debug desactivado para producción
    app.run(host='0.0.0.0', port=5000, debug=False)
