import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import winsound
import time
import os

# Server connection details
HOST = '127.0.0.1'
PORT = 12345

class UI:
    def __init__(self, root):
        self.root = root
        self.root.title("LU-Connect Chat")

        self.username = None
        self.client_socket = None
        self.sound_enabled = True
        
        # Login/Register Frame
        self.auth_frame = tk.Frame(self.root)
        tk.Label(self.auth_frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.auth_frame)
        self.username_entry.pack()
        tk.Label(self.auth_frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.auth_frame, show="*")
        self.password_entry.pack()
        self.login_button = tk.Button(self.auth_frame, text="Login", command=lambda: self.authenticate("login"))
        self.login_button.pack()
        self.register_button = tk.Button(self.auth_frame, text="Register", command=lambda: self.authenticate("register"))
        self.register_button.pack()
        self.auth_frame.pack()

        # Chat Frame (Hidden initially)
        self.chat_frame = tk.Frame(self.root)
        self.text_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state='disabled', height=15, width=50)
        self.text_area.pack()
        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT)
        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        self.sound_button = tk.Button(self.chat_frame, text="Mute", command=self.toggle_sound)
        self.sound_button.pack()
        
    def authenticate(self, action):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            self.client_socket.sendall(action.encode())
            # Wait for server prompt before sending further data.
            self.client_socket.recv(1024)
            self.client_socket.sendall(username.encode())
            self.client_socket.recv(1024)
            self.client_socket.sendall(password.encode())
            response = self.client_socket.recv(1024).decode()
            if "Invalid" in response or "Username already exists" in response:
                messagebox.showerror("Authentication Failed", response)
                self.client_socket.close()
                return
            if action == "register":
                messagebox.showinfo("Registered", "You can now log in.")
                self.client_socket.close()
                return
            self.username = username
            self.auth_frame.pack_forget()
            self.chat_frame.pack()
            if "in the queue" in response:
                self.message_entry.config(state='disabled')
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
        # file transfer command: /sendfile <filepath>
        if message.startswith("/sendfile"):
            parts = message.split(maxsplit=1)
            if len(parts) < 2:
                messagebox.showerror("Error", "Usage: /sendfile <filepath>")
                return
            filepath = parts[1]
            allowed_extensions = ['.docx', '.pdf', '.jpeg']
            ext = os.path.splitext(filepath)[1].lower()
            if ext not in allowed_extensions:
                messagebox.showerror("Error", "File type not allowed. Only .docx, .pdf, and .jpeg are allowed.")
                return
            try:
                with open(filepath, "rb") as f:
                    file_data = f.read()
                filesize = len(file_data)
                filename = os.path.basename(filepath)
                header = f"/FILE {filename} {filesize}\n"
                self.client_socket.sendall(header.encode('utf-8'))
                # Small delay to help separate header and binary data.
                time.sleep(0.1)
                self.client_socket.sendall(file_data)
                self.text_area.config(state='normal')
                self.text_area.insert(tk.END, f"Sent file: {filename}\n")
                self.text_area.config(state='disabled')
                self.text_area.yview(tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"File transfer failed: {e}")
            self.message_entry.delete(0, tk.END)
        else:
            try:
                self.client_socket.sendall(message.encode('utf-8'))
                self.message_entry.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Connection lost")
                self.root.quit()

    # Helper: read from socket until newline is encountered.
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

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                # Check if this is a file transfer (binary data starts with /FILE)
                if data.startswith(b"/FILE"):
                    if b'\n' in data:
                        header, remainder = data.split(b'\n', 1)
                    else:
                        header = data + self.recv_line(self.client_socket)
                        remainder = b""
                    header = header.decode('utf-8').strip()
                    parts = header.split()
                    if len(parts) < 3:
                        self.text_area.config(state='normal')
                        self.text_area.insert(tk.END, "Received invalid file header.\n")
                        self.text_area.config(state='disabled')
                        continue
                    filename = parts[1]
                    
                    filesize = int(parts[2])
                    

                    file_data = remainder
                    while len(file_data) < filesize:
                        chunk = self.client_socket.recv(min(1024, filesize - len(file_data)))
                        if not chunk:
                            break
                        file_data += chunk

                    # Save the received file locally.
                    with open(filename, "wb") as f:
                        f.write(file_data)
                    
                    self.text_area.config(state='normal')
                    self.text_area.insert(tk.END, f"Received file: {filename}\n")
                    self.text_area.config(state='disabled')
                    self.text_area.yview(tk.END)
                    self.play_notification()
                else:
                    # Normal text message.
                    text = data.decode('utf-8').strip()
                    self.text_area.config(state='normal')
                    self.text_area.insert(tk.END, text + "\n")
                    self.text_area.config(state='disabled')
                    self.text_area.yview(tk.END)
                    self.play_notification()
                    if "in the queue" in text:
                        self.message_entry.config(state='disabled')
                    if "It's your turn" in text:
                        self.message_entry.config(state='normal')
            except Exception as e:
                print(f"Error in receiving messages: {e}")
                break
    
    def play_notification(self):
        if self.sound_enabled:
            winsound.MessageBeep()
    
    def toggle_sound(self):
        self.sound_enabled = not self.sound_enabled
        self.sound_button.config(text="Unmute" if not self.sound_enabled else "Mute")

root = tk.Tk()
app = UI(root)
root.mainloop()
