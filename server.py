import socket
import threading
import sqlite3
import bcrypt
from datetime import datetime
import time

HOST = '0.0.0.0'
PORT = 12345
MAX_CONNECTIONS = 3

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()  # Allow more than MAX_CONNECTIONS to connect

semaphore = threading.Semaphore(MAX_CONNECTIONS)
clients = {}  # {username: socket}

waiting_queue = []
waiting_lock = threading.Lock()

# Initialize the database
def init_db():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password BLOB NOT NULL
    )''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()

init_db()

def register_user(username, password):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return True  # Success
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Username exists

def authenticate_user(username, password):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[0]):
        return True  # Valid login
    return False  # Invalid credentials

def save_message(sender, recipient, message):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)", 
                   (sender, recipient, message))
    
    conn.commit()
    conn.close()

def get_user_messages(username):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender, message, timestamp FROM messages
        WHERE recipient = ? OR recipient = 'ALL'
        ORDER BY timestamp DESC LIMIT 10
    """, (username,))

    messages = cursor.fetchall()
    conn.close()
    return messages

def handle_client(client_socket, client_address):
    username = None
    try:
        client_socket.sendall("Enter 'register' to create an account or 'login' to sign in: ".encode('utf-8'))
        choice = client_socket.recv(1024).decode('utf-8').strip().lower()

        if choice == "register":
            client_socket.sendall("Enter a username: ".encode('utf-8'))
            username = client_socket.recv(1024).decode('utf-8').strip()

            client_socket.sendall("Enter a password: ".encode('utf-8'))
            password = client_socket.recv(1024).decode('utf-8').strip()

            if register_user(username, password):
                client_socket.sendall("Registration successful! You can now login.\n".encode('utf-8'))
            else:
                client_socket.sendall("Username already exists. Try again.\n".encode('utf-8'))
            client_socket.close()
            return

        elif choice == "login":
            client_socket.sendall("Enter your username: ".encode('utf-8'))
            username = client_socket.recv(1024).decode('utf-8').strip()

            client_socket.sendall("Enter your password: ".encode('utf-8'))
            password = client_socket.recv(1024).decode('utf-8').strip()

            if authenticate_user(username, password):
                if semaphore.acquire(blocking=False):
                    client_socket.sendall(f"Welcome, {username}! Loading chat history...\n".encode('utf-8'))
                    messages = get_user_messages(username)
                    for sender, message, timestamp in reversed(messages):
                        client_socket.sendall(f"[{timestamp}] {sender}: {message}\n".encode('utf-8'))
                    client_socket.sendall("Type @recipient message to send a DM, or type normally to broadcast.\n".encode('utf-8'))
                    clients[username] = client_socket
                else:
                    with waiting_lock:
                        waiting_queue.append((username, client_socket))
                        position = len(waiting_queue)
                    client_socket.sendall(f"Chat is full. You are in position {position} in the queue. Please wait until you are allowed to chat.\n".encode('utf-8'))
                    
                    while True:
                        with waiting_lock:
                            if waiting_queue and waiting_queue[0][0] == username:
                                break
                            else:
                                try:
                                    pos = waiting_queue.index((username, client_socket)) + 1
                                except ValueError:
                                    pos = 1
                        client_socket.sendall(f"You are in position {pos} in the queue.\n".encode('utf-8'))
                        time.sleep(2)
                    
                    semaphore.acquire() #bloacks until slot is free
                    with waiting_lock:
                        if waiting_queue and waiting_queue[0][0] == username:
                            waiting_queue.pop(0)
                    client_socket.sendall(f"It's your turn, {username}! Loading chat history...\n".encode('utf-8'))
                    messages = get_user_messages(username)
                    for sender, message, timestamp in reversed(messages):
                        client_socket.sendall(f"[{timestamp}] {sender}: {message}\n".encode('utf-8'))
                    client_socket.sendall("Type @recipient message to send a DM, or type normally to broadcast.\n".encode('utf-8'))
                    clients[username] = client_socket
            else:
                client_socket.sendall("Invalid username or password. Disconnecting...\n".encode('utf-8'))
                client_socket.close()
                return
        else:
            client_socket.sendall("Invalid choice. Disconnecting...\n".encode('utf-8'))
            client_socket.close()
            return

        ####################################Chat loop:####################################
        while True:
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data:
                break

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"Received from {username}: {data}")

            if data.startswith("@"):
                try:
                    recipient, message = data.split(" ", 1)
                    recipient = recipient[1:]

                    if recipient in clients:
                        clients[recipient].sendall(f"[{timestamp}] {username}: {message}\n".encode('utf-8'))
                        save_message(username, recipient, message)
                    else:
                        client_socket.sendall("Recipient not found.\n".encode('utf-8'))
                except ValueError:
                    client_socket.sendall("Invalid format. Use @username message.\n".encode('utf-8'))
            else:
                for user, sock in list(clients.items()):
                    if user != username:
                        try:
                            sock.sendall(f"[{timestamp}] {username}: {data}\n".encode('utf-8'))
                        except:
                            del clients[user]
                save_message(username, "ALL", data)
    except ConnectionResetError:
        print(f"User '{username}' disconnected unexpectedly.")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        print(f"Connection from {client_address} closed.")
        if username in clients:
            del clients[username]
            semaphore.release()
        client_socket.close()

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
