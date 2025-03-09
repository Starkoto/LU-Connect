import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading

# Server connection details
HOST = '127.0.0.1'
PORT = 12345

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("LU-Connect Chat")

        self.username = None
        self.client_socket = None
        
        # Login Frame
        self.login_frame = tk.Frame(self.root)
        tk.Label(self.login_frame, text="Username:").pack()
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack()
        tk.Label(self.login_frame, text="Password:").pack()
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack()
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.pack()
        self.login_frame.pack()

        # Chat Frame (Hidden initially)
        self.chat_frame = tk.Frame(self.root)
        self.text_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, state='disabled', height=15, width=50)
        self.text_area.pack()
        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT)
        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        # Connect to server
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            self.client_socket.sendall(b"login")
            self.client_socket.recv(1024)  # Consume response
            self.client_socket.sendall(username.encode())
            self.client_socket.recv(1024)  # Consume response
            self.client_socket.sendall(password.encode())
            response = self.client_socket.recv(1024).decode()
            
            if "Invalid" in response:
                messagebox.showerror("Login Failed", response)
                self.client_socket.close()
                return
            
            self.username = username
            self.login_frame.pack_forget()
            self.chat_frame.pack()
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            
    def send_message(self):
        message = self.message_entry.get().strip()
        if message:
            try:
                self.client_socket.sendall(message.encode())
                self.message_entry.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Connection lost")
                self.root.quit()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    self.text_area.config(state='normal')
                    self.text_area.insert(tk.END, message + "\n")
                    self.text_area.config(state='disabled')
                    self.text_area.yview(tk.END)
            except:
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
