from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_session import Session

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Replace with a strong secret key in production

# Flask-Session Configuration (Using filesystem)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def init_db():
    """Initialize the SQLite database with necessary tables."""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'User'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,  -- This should remain NOT NULL because it references the creator
    task_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    progress INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    deadline TEXT,
    assigned_to INTEGER,  -- Make this field nullable (can be NULL)
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(assigned_to) REFERENCES users(id)
)''')


    conn.commit()
    conn.close()


# Initialize the database
init_db()

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    """Admin registration."""
    ADMIN_KEY = "yalla"  # Replace with a secure admin key

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        admin_key = request.form.get('admin_key').strip()

        if not username or not email or not password or not confirm_password or not admin_key:
            flash("Please fill in all the fields.", "danger")
            return redirect(url_for('register_admin'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register_admin'))

        if admin_key != ADMIN_KEY:
            flash("Invalid admin key. Access denied.", "danger")
            return redirect(url_for('register_admin'))

        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashed_password, 'Admin'))  # Set role to Admin
            conn.commit()
            conn.close()
            flash("Admin account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists.", "danger")
            return redirect(url_for('register_admin'))

    return render_template('register_admin.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("Please fill in all the fields.", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashed_password, 'User'))  # Set role to User
            conn.commit()
            conn.close()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists.", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """Redirect to the appropriate dashboard based on user role."""
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    if session.get('role') == 'Admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')

        # Fetch the user from the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            # Successful login
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]  # Check the user role
            flash("Login successful!", "success")
            if session['role'] == 'Admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin-specific dashboard."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # تحويل النتائج إلى قواميس
    c = conn.cursor()

    # Fetch users
    c.execute("SELECT id, username, email, role FROM users")
    users = [dict(user) for user in c.fetchall()]

    # Fetch tasks with assigned user's username
    c.execute("""
        SELECT tasks.id, tasks.task_name, tasks.status, tasks.progress, 
               tasks.created_at, tasks.deadline, users.email AS assigned_to
        FROM tasks
        LEFT JOIN users ON tasks.assigned_to = users.id
    """)
    tasks = [dict(task) for task in c.fetchall()]

    conn.close()

    # Add the current date
    current_date = datetime.now().strftime('%Y-%m-%d')

    return render_template('admin_dashboard.html', users=users, tasks=tasks, current_date=current_date)



@app.route('/user_dashboard')
def user_dashboard():
    """User-specific dashboard."""
    if 'user_id' not in session or session.get('role') == 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    # Fetch user-specific data if necessary
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE user_id = ?", (session['user_id'],))
    tasks = c.fetchall()
    conn.close()

    return render_template('user_dashboard.html', tasks=tasks)


@app.route('/change_task_status/<int:task_id>', methods=['POST'])
def change_task_status(task_id):
    """Change the status of a task."""
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    new_status = request.form.get('status')

    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?", (new_status, task_id, session['user_id']))
        conn.commit()
        conn.close()
        flash("Task status updated successfully!", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('user_dashboard'))


#================== CRUD ===================

@app.route('/add_user', methods=['POST'])
def add_user():
    """Add a new user."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    username = request.form.get('username').strip()
    email = request.form.get('email').strip()
    password = request.form.get('password')
    role = request.form.get('role', 'User')  # Default to 'User'

    if not username or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    hashed_password = generate_password_hash(password)
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                  (username, email, hashed_password, role))
        conn.commit()
        conn.close()
        flash("User added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("Username or Email already exists.", "danger")
    return redirect(url_for('admin_dashboard'))



@app.route('/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    """Edit an existing user."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    username = request.form.get('username').strip()
    email = request.form.get('email').strip()

    if not username or not email:
        flash("All fields are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (username, email, user_id))
        conn.commit()
        conn.close()
        flash("User updated successfully!", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Delete a user."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash("User deleted successfully!", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/change_role/<int:user_id>', methods=['POST'])
def change_role(user_id):
    """Change the role of a user."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    new_role = request.form.get('role')  # Fetch the role value from the form
    if new_role not in ['User', 'Admin']:  # Valid roles
        flash("Invalid role value.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        flash("User role updated successfully!", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred while updating the role: {e}", "danger")
    return redirect(url_for('admin_dashboard'))



#=============TASKS MANAGEMENT ===================#
@app.route('/add_task', methods=['POST'])
def add_task():
    """إضافة مهمة جديدة."""
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Access denied. Please log in as an Admin.", "danger")
        return redirect(url_for('login'))  # إعادة توجيه إلى صفحة تسجيل الدخول إذا لم يكن المستخدم مسجلاً أو ليس مسؤولاً

    task_name = request.form.get('task_name')
    assigned_email = request.form.get('assigned_to')  # البريد الإلكتروني للمستخدم
    deadline = request.form.get('deadline')

    if not task_name or not assigned_email or not deadline:
        flash("Task name, assigned user email, and deadline are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()

            # البحث عن المستخدم باستخدام البريد الإلكتروني
            c.execute("SELECT id FROM users WHERE email = ?", (assigned_email,))
            user = c.fetchone()

            if user is None:
                flash("User not found. Please ensure the email is correct.", "danger")
                return redirect(url_for('admin_dashboard'))

            assigned_to = user[0]  # الحصول على معرف المستخدم من النتيجة

            # الحصول على معرف المستخدم الذي قام بتسجيل الدخول
            created_by = session['user_id']  # يجب أن يكون هذا معرف المستخدم الذي قام بتسجيل الدخول

            # طباعة القيم للتحقق
            print(f"Task Name: {task_name}")
            print(f"Assigned Email: {assigned_email}")
            print(f"Assigned To (User ID): {assigned_to}")
            print(f"Created By (User ID): {created_by}")

            # إدخال المهمة مع تعيين user_id للمسؤول الذي قام بإنشاء المهمة
            c.execute("""
                INSERT INTO tasks (user_id, task_name, assigned_to, deadline)
                VALUES (?, ?, ?, ?)
            """, (created_by, task_name, assigned_to, deadline))

            conn.commit()  # تأكيد التغييرات في قاعدة البيانات
            flash("Task added successfully!", "success")

    except sqlite3.Error as e:
        flash(f"An error occurred while adding the task: {e}", "danger")

    return redirect(url_for('admin_dashboard'))






# @app.route('/edit_task/<int:task_id>', methods=['POST'])
# def edit_task(task_id):
#     if 'user_id' not in session or session['role'] != 'Admin':
#         flash('Access denied.', 'danger')
#         return redirect(url_for('login'))

#     task_name = request.form.get('task_name')
#     status = request.form.get('status')
#     progress = request.form.get('progress')
#     user_id = request.form.get('user_id')
#     deadline = request.form.get('deadline')

#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("""
#             UPDATE tasks
#             SET task_name = ?, status = ?, progress = ?, user_id = ?, deadline = ?
#             WHERE id = ?
#         """, (task_name, status, progress, user_id, deadline, task_id))
#         conn.commit()
#         conn.close()
#         flash('Task updated successfully!', 'success')
#     except sqlite3.Error as e:
#         flash(f'An error occurred: {e}', 'danger')
#     return redirect(url_for('admin_dashboard'))


# @app.route('/delete_task/<int:task_id>', methods=['POST'])
# def delete_task(task_id):
#     if 'user_id' not in session or session['role'] != 'Admin':
#         flash('Access denied.', 'danger')
#         return redirect(url_for('login'))

#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
#         conn.commit()
#         conn.close()
#         flash('Task deleted successfully!', 'success')
#     except sqlite3.Error as e:
#         flash(f'An error occurred: {e}', 'danger')
#     return redirect(url_for('admin_dashboard'))


@app.route('/edit_task/<int:task_id>', methods=['POST'])
def edit_task(task_id):
    if 'user_id' not in session or session['role'] != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    task_name = request.form.get('task_name')
    status = request.form.get('status')
    progress = request.form.get('progress')
    user_id = request.form.get('user_id')  # تأكد من أن هذا الحقل يحتوي على قيمة صحيحة
    deadline = request.form.get('deadline')

    # إذا كانت user_id فارغة، نقوم بتعيين user_id من الجلسة
    if not user_id:
        user_id = session['user_id']  # تعيين user_id من الجلسة إذا لم يتم إدخاله

    # جمل الطباعة لمراجعة القيم المدخلة
    print(f"Editing Task ID: {task_id}")
    print(f"Task Name: {task_name}")
    print(f"Status: {status}")
    print(f"Progress: {progress}")
    print(f"Assigned User ID: {user_id}")
    print(f"Deadline: {deadline}")

    try:
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()

            # تحقق من أن user_id موجود في قاعدة البيانات
            if not user_id:
                flash('User ID is missing or invalid.', 'danger')
                return redirect(url_for('admin_dashboard'))

            # تحقق من أن user_id المدخل موجود في جدول users
            c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            if user is None:
                flash(f"User ID {user_id} not found.", "danger")
                return redirect(url_for('admin_dashboard'))

            # تحديث المهمة
            c.execute("""
                UPDATE tasks
                SET task_name = ?, status = ?, progress = ?, user_id = ?, deadline = ?
                WHERE id = ?
            """, (task_name, status, progress, user_id, deadline, task_id))

            conn.commit()  # تأكيد التغييرات في قاعدة البيانات
            flash('Task updated successfully!', 'success')

            # جملة الطباعة بعد التحديث
            print(f"Task ID {task_id} has been updated successfully.")

    except sqlite3.Error as e:
        flash(f'An error occurred: {e}', 'danger')
        print(f"Error occurred: {e}")

    return redirect(url_for('admin_dashboard'))






@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session or session['role'] != 'Admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    try:
        # استخدام with لإدارة الاتصال بشكل صحيح
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()

            # حذف المهمة
            c.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()  # تأكيد التغييرات في قاعدة البيانات
            flash('Task deleted successfully!', 'success')

    except sqlite3.Error as e:
        flash(f'An error occurred: {e}', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    """Logout the current user."""
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)







# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from werkzeug.security import generate_password_hash, check_password_hash
# import sqlite3
# from flask_session import Session

# app = Flask(__name__)
# app.secret_key = "your_secret_key_here"  # Replace with a strong secret key in production

# # Flask-Session Configuration (Using filesystem)
# app.config["SESSION_TYPE"] = "filesystem"
# Session(app)

# def init_db():
#     """Initialize the SQLite database with necessary tables."""
#     conn = sqlite3.connect('database.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         username TEXT UNIQUE NOT NULL,
#         email TEXT UNIQUE NOT NULL,
#         password TEXT NOT NULL,
#         is_admin BOOLEAN DEFAULT 0,
#         role TEXT DEFAULT 'User'
#     )''')
#     c.execute('''CREATE TABLE IF NOT EXISTS tasks (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         user_id INTEGER NOT NULL,
#         task_name TEXT NOT NULL,
#         status TEXT NOT NULL DEFAULT 'Pending',
#         deadline TEXT,
#         FOREIGN KEY(user_id) REFERENCES users(id)
#     )''')
#     conn.commit()
#     conn.close()


# # Initialize the database
# init_db()

# @app.route('/')
# def index():
#     """Home page."""
#     return render_template('index.html')


# @app.route('/register_admin', methods=['GET', 'POST'])
# def register_admin():
#     """Admin registration."""
#     ADMIN_KEY = "yalla"  # Replace with a secure admin key

#     if request.method == 'POST':
#         username = request.form.get('username').strip()
#         email = request.form.get('email').strip()
#         password = request.form.get('password')
#         confirm_password = request.form.get('confirm_password')
#         admin_key = request.form.get('admin_key').strip()

#         if not username or not email or not password or not confirm_password or not admin_key:
#             flash("Please fill in all the fields.", "danger")
#             return redirect(url_for('register_admin'))

#         if password != confirm_password:
#             flash("Passwords do not match.", "danger")
#             return redirect(url_for('register_admin'))

#         if admin_key != ADMIN_KEY:
#             flash("Invalid admin key. Access denied.", "danger")
#             return redirect(url_for('register_admin'))

#         hashed_password = generate_password_hash(password)
#         try:
#             conn = sqlite3.connect('database.db')
#             c = conn.cursor()
#             c.execute("INSERT INTO users (username, email, password, is_admin, role) VALUES (?, ?, ?, ?, ?)",
#                       (username, email, hashed_password, 1, 'Admin'))  # Set role to Admin
#             conn.commit()
#             conn.close()
#             flash("Admin account created successfully! Please log in.", "success")
#             return redirect(url_for('login'))
#         except sqlite3.IntegrityError:
#             flash("Username or Email already exists.", "danger")
#             return redirect(url_for('register_admin'))

#     return render_template('register_admin.html')








# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     """User registration."""
#     if request.method == 'POST':
#         username = request.form.get('username').strip()
#         email = request.form.get('email').strip()
#         password = request.form.get('password')
#         confirm_password = request.form.get('confirm_password')

#         if not username or not email or not password or not confirm_password:
#             flash("Please fill in all the fields.", "danger")
#             return redirect(url_for('register'))

#         if password != confirm_password:
#             flash("Passwords do not match.", "danger")
#             return redirect(url_for('register'))

#         hashed_password = generate_password_hash(password)
#         try:
#             conn = sqlite3.connect('database.db')
#             c = conn.cursor()
#             c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
#                       (username, email, hashed_password, 'User'))  # Set role to User
#             conn.commit()
#             conn.close()
#             flash("Account created successfully! Please log in.", "success")
#             return redirect(url_for('login'))
#         except sqlite3.IntegrityError:
#             flash("Username or Email already exists.", "danger")
#             return redirect(url_for('register'))

#     return render_template('register.html')

# @app.route('/dashboard')
# def dashboard():
#     """Redirect to the appropriate dashboard based on user role."""
#     if 'user_id' not in session:
#         flash("Please log in first.", "warning")
#         return redirect(url_for('login'))

#     if session.get('is_admin'):
#         return redirect(url_for('admin_dashboard'))
#     return redirect(url_for('user_dashboard'))


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     """User login."""
#     if request.method == 'POST':
#         identifier = request.form.get('username').strip()
#         password = request.form.get('password')

#         # Fetch the user from the database
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
#         user = c.fetchone()
#         conn.close()

#         if user and check_password_hash(user[3], password):
#             # Successful login
#             session['user_id'] = user[0]
#             session['username'] = user[1]
#             session['is_admin'] = bool(user[4])  # Check if the user is admin
#             flash("Login successful!", "success")
#             if session['is_admin']:
#                 return redirect(url_for('admin_dashboard'))
#             else:
#                 return redirect(url_for('user_dashboard'))
#         else:
#             flash("Invalid username/email or password.", "danger")
#             return redirect(url_for('login'))

#     return render_template('login.html')


# @app.route('/admin_dashboard')
# def admin_dashboard():
#     """Admin-specific dashboard."""
#     if 'user_id' not in session or not session.get('is_admin'):
#         flash("Access denied.", "danger")
#         return redirect(url_for('login'))

#     conn = sqlite3.connect('database.db')
#     conn.row_factory = sqlite3.Row  # يضمن إرجاع الصفوف كقواميس
#     c = conn.cursor()
#     c.execute("SELECT id, username, email FROM users")
#     users = c.fetchall()
#     c.execute("SELECT id, task_name, status FROM tasks")
#     tasks = c.fetchall()
#     conn.close()

#     return render_template('admin_dashboard.html', users=users, tasks=tasks)

# @app.route('/add_user', methods=['POST'])
# def add_user():
#     """Add a new user."""
#     if 'user_id' not in session or not session.get('is_admin'):
#         flash("Access denied.", "danger")
#         return redirect(url_for('login'))

#     username = request.form.get('username').strip()
#     email = request.form.get('email').strip()
#     password = request.form.get('password')
#     role = request.form.get('role', 'User')  # Default to 'User'

#     if not username or not email or not password:
#         flash("All fields are required.", "danger")
#         return redirect(url_for('admin_dashboard'))

#     hashed_password = generate_password_hash(password)
#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
#                   (username, email, hashed_password, role))
#         conn.commit()
#         conn.close()
#         flash("User added successfully!", "success")
#     except sqlite3.IntegrityError:
#         flash("Username or Email already exists.", "danger")
#     return redirect(url_for('admin_dashboard'))


# @app.route('/delete_user/<int:user_id>', methods=['POST'])
# def delete_user(user_id):
#     """Delete a user."""
#     if 'user_id' not in session or not session.get('is_admin'):
#         flash("Access denied.", "danger")
#         return redirect(url_for('login'))

#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("DELETE FROM users WHERE id = ?", (user_id,))
#         conn.commit()
#         conn.close()
#         flash("User deleted successfully!", "success")
#     except sqlite3.Error as e:
#         flash(f"An error occurred: {e}", "danger")
#     return redirect(url_for('admin_dashboard'))

# @app.route('/delete_task/<int:task_id>', methods=['POST'])
# def delete_task(task_id):
#     """Delete a task."""
#     if 'user_id' not in session or not session.get('is_admin'):
#         flash("Access denied.", "danger")
#         return redirect(url_for('login'))

#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
#         conn.commit()
#         conn.close()
#         flash("Task deleted successfully!", "success")
#     except sqlite3.Error as e:
#         flash(f"An error occurred: {e}", "danger")
#     return redirect(url_for('admin_dashboard'))

# @app.route('/change_role/<int:user_id>', methods=['POST'])
# def change_role(user_id):
#     """Change the role of a user."""
#     if 'user_id' not in session or not session.get('is_admin'):
#         flash("Access denied.", "danger")
#         return redirect(url_for('login'))

#     new_role = request.form.get('role')  # Fetch the role value from the form
#     if new_role not in ['User', 'Admin']:  # Valid roles
#         flash("Invalid role value.", "danger")
#         return redirect(url_for('admin_dashboard'))

#     try:
#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()
#         c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
#         conn.commit()
#         conn.close()
#         flash("User role updated successfully!", "success")
#     except sqlite3.Error as e:
#         flash(f"An error occurred while updating the role: {e}", "danger")
#     return redirect(url_for('admin_dashboard'))




# @app.route('/logout')
# def logout():
#     """Logout the current user."""
#     session.clear()
#     flash("Logged out successfully.", "info")
#     return redirect(url_for('index'))

# if __name__ == '__main__':
#     app.run(debug=True)