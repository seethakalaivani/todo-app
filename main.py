import mysql.connector
import tkinter as tk
from tkinter import messagebox, ttk
from tkcalendar import DateEntry
from plyer import notification
import bcrypt
import datetime

# Database Connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",  # Change this to your MySQL username
    password="root",  # Change this to your MySQL password
    database="todo_db"
)
cursor = conn.cursor()

# Global variable for logged-in user
current_user_id = None

def check_due_tasks():
    today = datetime.date.today()
    cursor.execute("SELECT task FROM tasks WHERE user_id=%s AND due_date=%s AND status='Pending'", (current_user_id, today))
    due_tasks = cursor.fetchall()

    if due_tasks:
        task_names = "\n".join([task[0] for task in due_tasks])
        print("DEBUG: Found due tasks →", task_names)  # ✅ Debug output

        notification.notify(
            title="⏰ Task Reminder!",
            message=f"You have tasks due today:\n{task_names}",
            timeout=10
        )
    else:
        print("DEBUG: No tasks due today.")  # ✅ Debug output


# Function to load tasks from database
def load_tasks():
    task_listbox.delete(0, tk.END)
    status_filter = filter_var.get()
    query = "SELECT id, task, due_date, status FROM tasks WHERE user_id=%s"
    params = [current_user_id]

    if status_filter != "All":
        query += " AND status=%s"
        params.append(status_filter)

    cursor.execute(query, tuple(params))
    tasks = cursor.fetchall()

    for task in tasks:
        task_listbox.insert(tk.END, f"{task[1]} - {task[2]} ({task[3]})")

# Function to add task
def add_task():
    task_text = task_entry.get()
    due_date = due_date_entry.get_date()

    if not task_text:
        messagebox.showerror("Error", "Task cannot be empty")
        return

    cursor.execute("INSERT INTO tasks (user_id, task, due_date) VALUES (%s, %s, %s)", (current_user_id, task_text, due_date))
    conn.commit()
    task_entry.delete(0, tk.END)
    load_tasks()

# Function to mark task as done
def mark_done():
    selected_task = task_listbox.get(tk.ACTIVE)
    if not selected_task:
        messagebox.showerror("Error", "No task selected")
        return

    task_name = selected_task.split(" - ")[0]
    cursor.execute("UPDATE tasks SET status='Completed' WHERE user_id=%s AND task=%s", (current_user_id, task_name))
    conn.commit()
    load_tasks()

# Function to remove task
def remove_task():
    selected_task = task_listbox.get(tk.ACTIVE)
    if not selected_task:
        messagebox.showerror("Error", "No task selected")
        return

    task_name = selected_task.split(" - ")[0]
    cursor.execute("DELETE FROM tasks WHERE user_id=%s AND task=%s", (current_user_id, task_name))
    conn.commit()
    load_tasks()

# Function to open the To-Do List
def open_todo_list():
    global task_listbox, task_entry, due_date_entry, filter_var

    root = tk.Tk()
    root.title("To-Do List")
    root.geometry("500x550")
    root.configure(bg="#F4D03F")

    tk.Label(root, text="📋 To-Do List", font=("Arial", 16, "bold"), bg="#F4D03F", fg="#283747").pack(pady=10)

    task_entry = tk.Entry(root, width=40, font=("Arial", 12))
    task_entry.pack(pady=5)

    due_date_entry = DateEntry(root, width=12, font=("Arial", 12), background='blue', foreground='white', borderwidth=2)
    due_date_entry.pack(pady=5)

    button_frame = tk.Frame(root, bg="#F4D03F")
    button_frame.pack(pady=5)

    tk.Button(button_frame, text="➕ Add Task", font=("Arial", 12), bg="#58D68D", fg="white", command=add_task).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="✔️ Mark Done", font=("Arial", 12), bg="#5DADE2", fg="white", command=mark_done).grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="❌ Remove", font=("Arial", 12), bg="#E74C3C", fg="white", command=remove_task).grid(row=0, column=2, padx=5)
    filter_var = tk.StringVar(value="All")

    filter_dropdown = ttk.Combobox(root, textvariable=filter_var, values=["All", "Pending", "Completed"], state="readonly")
    filter_dropdown.pack(pady=5)

    # Bind the filter selection change event
    filter_dropdown.bind("<<ComboboxSelected>>", lambda event: load_tasks())
    
    task_listbox = tk.Listbox(root, width=60, height=15, font=("Arial", 12))
    task_listbox.pack(pady=10)

    load_tasks()
    check_due_tasks()

    root.mainloop()

# Function to register user
def register_user():
    username = reg_username_entry.get()
    password = reg_password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required")
        return

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    conn.commit()
    messagebox.showinfo("Success", "Registration Successful!")
    reg_window.destroy()

# Function to open registration window
def register_window():
    global reg_window, reg_username_entry, reg_password_entry

    reg_window = tk.Toplevel(login_window)
    reg_window.title("Register")
    reg_window.geometry("300x250")

    tk.Label(reg_window, text="Username:").pack()
    reg_username_entry = tk.Entry(reg_window)
    reg_username_entry.pack()

    tk.Label(reg_window, text="Password:").pack()
    reg_password_entry = tk.Entry(reg_window, show="*")
    reg_password_entry.pack()

    tk.Button(reg_window, text="Register", command=register_user).pack(pady=10)

# Function to login user
def login_user():
    global current_user_id

    username = username_entry.get()
    password = password_entry.get()

    cursor.execute("SELECT id, password FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        current_user_id = user[0]
        messagebox.showinfo("Success", "Login Successful!")
        login_window.destroy()
        open_todo_list()
    else:
        messagebox.showerror("Error", "Invalid Credentials")

# Open login window
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("300x250")

tk.Label(login_window, text="Username:").pack()
username_entry = tk.Entry(login_window)
username_entry.pack()

tk.Label(login_window, text="Password:").pack()
password_entry = tk.Entry(login_window, show="*")
password_entry.pack()

tk.Button(login_window, text="Login", command=login_user).pack(pady=10)
tk.Button(login_window, text="Register", command=register_window).pack()

login_window.mainloop()
