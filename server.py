import socket
import threading
import sqlite3
import bcrypt
from datetime import datetime
import time
from cryptography.fernet import Fernet

HOST = '0.0.0.0'
PORT = 12345
MAX_CONNECTIONS = 3

class ChatServer:
    def __init__(self, host, port, max_connections):
        self.host = host
        self.port = port
        self.max_connections = max_connections

        # Create and bind the server socket.
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()

        # Initialize connection management objects.
        self.semaphore = threading.Semaphore(self.max_connections)
        self.clients = {}          # {username: socket}
        self.waiting_queue = []    # [(username, socket)]
        self.waiting_lock = threading.Lock()

        # Generate an encryption key and create a cipher object.
        self.ENCRYPTION_KEY = Fernet.generate_key()
        self.cipher_suite = Fernet(self.ENCRYPTION_KEY)

        # Initialize the database.
        self.init_db()

    def init_db(self):
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

    def register_user(self, username, password):
        conn = sqlite3.connect("messages.db")
        cursor = conn.cursor()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False

    def authenticate_user(self, username, password):
        conn = sqlite3.connect("messages.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[0]):
            return True
        return False

    def save_message(self, sender, recipient, message):
        # encrypt the message.
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8')).decode('utf-8')
        conn = sqlite3.connect("messages.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)", 
                       (sender, recipient, encrypted_message))
        conn.commit()
        conn.close()

    def get_user_messages(self, username):
        conn = sqlite3.connect("messages.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender, message, timestamp FROM messages
            WHERE recipient = ? OR recipient = 'ALL'
            ORDER BY timestamp DESC LIMIT 10
        """, (username,))
        messages = cursor.fetchall()
        conn.close()
        # Decrypt messages before returning them.
        decrypted_messages = []
        for sender, encrypted_message, timestamp in messages:
            try:
                decrypted_text = self.cipher_suite.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
            except Exception:
                decrypted_text = "[Error decrypting message]"
            decrypted_messages.append((sender, decrypted_text, timestamp))
        return decrypted_messages

    # Helper: reads from socket until newline is encountered.
    def recv_line(self, sock):
        line = b""
        while True:
            char = sock.recv(1)
            if not char:
                break
            line += char
            if char == b'\n':
                break
        return line 

    def handle_client(self, client_socket, client_address):
        username = None
        try:
            client_socket.sendall("Type 'register' to register or 'login' to log in: ".encode('utf-8')) # testing before ui was added
            choice = client_socket.recv(1024).decode('utf-8').strip().lower()

            #server recieves either register or login from the client after button press
            if choice == "register": #handles register
                client_socket.sendall("Enter a username: ".encode('utf-8'))
                username = client_socket.recv(1024).decode('utf-8').strip()
                client_socket.sendall("Enter a password: ".encode('utf-8'))
                password = client_socket.recv(1024).decode('utf-8').strip()
                if self.register_user(username, password):
                    client_socket.sendall("Registered, You can now log in.\n".encode('utf-8'))
                else:
                    client_socket.sendall("Username already exists. Try again.\n".encode('utf-8'))
                client_socket.close()
                return

            elif choice == "login": #handles login
                client_socket.sendall("Enter your username: ".encode('utf-8'))
                username = client_socket.recv(1024).decode('utf-8').strip()
                client_socket.sendall("Enter your password: ".encode('utf-8'))
                password = client_socket.recv(1024).decode('utf-8').strip()
                if self.authenticate_user(username, password):
                    if self.semaphore.acquire(blocking=False):
                        client_socket.sendall(f"Welcome, {username}! Loading chat history...\n".encode('utf-8'))
                        messages = self.get_user_messages(username)
                        for sender, message, timestamp in reversed(messages):
                            client_socket.sendall(f"[{timestamp}] {sender}: {message}\n".encode('utf-8'))
                        client_socket.sendall("Type @recipient message to send a message directly, or type normally to broadcast to everyone.\n".encode('utf-8'))
                        self.clients[username] = client_socket
                    else:
                        with self.waiting_lock:
                            self.waiting_queue.append((username, client_socket))
                            position = len(self.waiting_queue)
                        client_socket.sendall(f"Chat is full. You are in position {position} in the queue.\n".encode('utf-8'))
                        
                        while True:
                            with self.waiting_lock:
                                if self.waiting_queue and self.waiting_queue[0][0] == username:
                                    break
                                else:
                                    try:
                                        pos = self.waiting_queue.index((username, client_socket)) + 1
                                    except ValueError:
                                        pos = 1
                            client_socket.sendall(f"You are in position {pos} in the queue.\n".encode('utf-8'))
                            time.sleep(2)
                        
                        self.semaphore.acquire()
                        with self.waiting_lock:
                            if self.waiting_queue and self.waiting_queue[0][0] == username:
                                self.waiting_queue.pop(0)
                        client_socket.sendall(f"It's your turn, {username}! Loading chat history...\n".encode('utf-8'))
                        messages = self.get_user_messages(username)
                        for sender, message, timestamp in reversed(messages):
                            client_socket.sendall(f"[{timestamp}] {sender}: {message}\n".encode('utf-8'))
                        client_socket.sendall("Type @recipient message to send a message directly, or type normally to broadcast to everyone.\n".encode('utf-8'))
                        self.clients[username] = client_socket
                else:
                    client_socket.sendall("Invalid username or password.\n".encode('utf-8'))
                    client_socket.close()
                    return
            else:
                return

            ######################################################## Chat loop: #########################################################

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                # check if the data is a file transfer
                if data.startswith(b"/FILE"):
                    if b'\n' in data:
                        header, remainder = data.split(b'\n', 1)
                    else:
                        header = data + self.recv_line(client_socket)
                        remainder = b""
                    header = header.decode('utf-8').strip()
                    parts = header.split()
                    if len(parts) < 3:
                        client_socket.sendall("Invalid file header.\n".encode('utf-8'))
                        continue
                    filename = parts[1]
                    filesize = int(parts[2])

                    file_data = remainder
                    while len(file_data) < filesize:
                        chunk = client_socket.recv(min(1024, filesize - len(file_data)))
                        if not chunk:
                            break
                        file_data += chunk

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    notification = f"[{timestamp}] {username} sent a file: {filename}\n"
                    #forward the file notification and data to all other clients.
                    for user, sock in list(self.clients.items()):
                        if user != username:
                            try:
                                sock.sendall(notification.encode('utf-8'))
                                file_header = f"/FILE {filename} {filesize}\n"
                                sock.sendall(file_header.encode('utf-8'))
                                sock.sendall(file_data)
                            except Exception as e:
                                print(f"Error sending file to {user}: {e}")
                                del self.clients[user]
                    continue

                # otherwise, assume it's a normal text message.
                try:
                    text = data.decode('utf-8').strip()
                except UnicodeDecodeError:
                    text = ""
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"Received from {username}: {text}")

                if text.startswith("@"):
                    recipient, msg = text.split(" ", 1)
                    recipient = recipient[1:]
                    if recipient in self.clients:
                        self.clients[recipient].sendall(f"[{timestamp}] {username}: {msg}\n".encode('utf-8'))
                        self.save_message(username, recipient, msg)
                    else:
                        client_socket.sendall("Recipient not found.\n".encode('utf-8'))
                else:
                    for user, sock in list(self.clients.items()):
                        if user != username:
                            try:
                                sock.sendall(f"[{timestamp}] {username}: {text}\n".encode('utf-8'))
                            except Exception as e:
                                print(f"Error sending message to {user}: {e}")
                                del self.clients[user]
                    self.save_message(username, "ALL", text)
        except ConnectionResetError:
            print(f"User '{username}' disconnected unexpectedly.")
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            print(f"Connection from {client_address} closed.")
            if username in self.clients:
                del self.clients[username]
                self.semaphore.release()
            client_socket.close()

    def start(self):
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()


server = ChatServer(HOST, PORT, MAX_CONNECTIONS)
server.start()
