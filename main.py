import tkinter as tk
from tkinter import messagebox
import mysql.connector
import bcrypt

# Database Connection
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="user"
    )

# Hash Password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check Password
def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password.encode('utf-8'))

# Register User
def register_user():
    username = reg_username.get()
    password = reg_password.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        db = connect_db()
        cursor = db.cursor()

        # Hashing password before storing
        hashed_password = hash_password(password).decode('utf-8')

        query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))
        db.commit()

        messagebox.showinfo("Success", "Registration Successful! Please Login.")
        reg_window.destroy()
        login_window()

        cursor.close()
        db.close()
    except mysql.connector.Error as e:
        messagebox.showerror("Database Error", str(e))

# Validate User Login
def validate_login():
    username = login_username.get()
    password = login_password.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        db = connect_db()
        cursor = db.cursor()

        query = "SELECT password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user and verify_password(user[0], password):
            messagebox.showinfo("Success", "Login Successful!")
            root.destroy()
        else:
            messagebox.showerror("Error", "Invalid Username or Password!")

        cursor.close()
        db.close()
    except mysql.connector.Error as e:
        messagebox.showerror("Database Error", str(e))

# Open Registration Window
def register_window():
    global reg_window, reg_username, reg_password

    reg_window = tk.Toplevel(root)
    reg_window.title("Register")
    reg_window.geometry("350x250")

    tk.Label(reg_window, text="Register", font=("Arial", 14, "bold")).pack(pady=5)
    tk.Label(reg_window, text="Username:").pack(pady=2)
    reg_username = tk.Entry(reg_window, width=30)
    reg_username.pack(pady=2)

    tk.Label(reg_window, text="Password:").pack(pady=2)
    reg_password = tk.Entry(reg_window, width=30, show="*")
    reg_password.pack(pady=2)

    tk.Button(reg_window, text="Register", command=register_user).pack(pady=10)

# Open Login Window
def login_window():
    global root, login_username, login_password

    root = tk.Tk()
    root.title("User Login")
    root.geometry("350x250")

    tk.Label(root, text="Login", font=("Arial", 14, "bold")).pack(pady=5)
    tk.Label(root, text="Username:").pack(pady=2)
    login_username = tk.Entry(root, width=30)
    login_username.pack(pady=2)

    tk.Label(root, text="Password:").pack(pady=2)
    login_password = tk.Entry(root, width=30, show="*")
    login_password.pack(pady=2)

    tk.Button(root, text="Login", command=validate_login).pack(pady=10)
    tk.Button(root, text="Register", command=register_window).pack(pady=5)

    root.mainloop()

# Start the Application
login_window()
