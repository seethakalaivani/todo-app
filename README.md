# 📝 To-Do App with Python, MySQL & Tkinter

A desktop-based To-Do List application built using **Python**, **Tkinter**, and **MySQL**. It allows user registration, login, task management, due date reminders, and status filtering (Pending/Completed).

## 🚀 Features

- ✅ User Registration & Login (with hashed passwords using bcrypt)
- ⏰ Due date reminders using system notifications
- 🗓️ Calendar widget to pick due dates (tkcalendar)
- ✔️ Mark tasks as completed
- ❌ Delete tasks
- 🔍 Filter tasks by status (All, Pending, Completed)

## 📦 Tools and Technologies used

- Python 3
- Tkinter (GUI)
- MySQL (Database)
- tkcalendar
- bcrypt
- plyer (notifications)

## 🔧 Setup Instructions

 1. Clone the repo:

git clone https://github.com/seethakalaivani/todo-app.git
cd todo-app

2. Install dependencies:

mysql-connector-python
tkcalendar
plyer
bcrypt

3. Create MySQL Database & Tables:

CREATE DATABASE todo_db;

USE todo_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    task VARCHAR(255),
    due_date DATE,
    status VARCHAR(20) DEFAULT 'Pending',
    FOREIGN KEY (user_id) REFERENCES users(id)
);
4. Run the App:

python main.py