import socket
import threading
import sqlite3
import bcrypt

HOST = '0.0.0.0'
PORT = 12345
MAX_CONNECTIONS = 3

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(MAX_CONNECTIONS)

semaphore = threading.Semaphore(MAX_CONNECTIONS)
clients = {}  # {username: socket}

def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password BLOB NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

def register_user(username, password):
    conn = sqlite3.connect("users.db")
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
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[0]):
        return True  # Valid login
    return False  # Invalid credentials

def handle_client(client_socket, client_address):
    with semaphore:
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
                    client_socket.sendall(f"Welcome, {username}! Type @recipient message to send a DM.\n".encode('utf-8'))
                    clients[username] = client_socket
                    print(f"User '{username}' connected from {client_address}.")
                else:
                    client_socket.sendall("Invalid username or password. Disconnecting...\n".encode('utf-8'))
                    client_socket.close()
                    return
            else:
                client_socket.sendall("Invalid choice. Disconnecting...\n".encode('utf-8'))
                client_socket.close()
                return

            while True:
                data = client_socket.recv(1024).decode('utf-8').strip()
                if not data:
                    break

                print(f"Received from {username}: {data}")

                if data.startswith("@"):
                    try:
                        recipient, message = data.split(" ", 1)
                        recipient = recipient[1:]

                        if recipient in clients:
                            clients[recipient].sendall(f"From {username}: {message}\n".encode('utf-8'))
                        else:
                            client_socket.sendall("Recipient not found.\n".encode('utf-8'))
                    except ValueError:
                        client_socket.sendall("Invalid format. Use @username message.\n".encode('utf-8'))
                else:
                    for user, client in clients.items():
                        if user != username:
                            try:
                                client.sendall(f"[From {username}]: {data}\n".encode('utf-8'))
                            except:
                                del clients[user]

        except ConnectionResetError:
            print(f"User '{username}' disconnected unexpectedly.")

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")

        finally:
            print(f"Connection from {client_address} closed.")
            if username in clients:
                del clients[username]
            client_socket.close()

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()

