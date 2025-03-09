import socket
import threading
import winsound
from datetime import datetime

HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

sound_enabled = True

print(client_socket.recv(1024).decode('utf-8'))  # Choose register/login
choice = input("> ").strip()
client_socket.sendall(choice.encode('utf-8'))

if choice == "register":
    print(client_socket.recv(1024).decode('utf-8'))  # Enter username
    username = input("> ").strip()
    client_socket.sendall(username.encode('utf-8'))

    print(client_socket.recv(1024).decode('utf-8'))  # Enter password
    password = input("> ").strip()
    client_socket.sendall(password.encode('utf-8'))

    print(client_socket.recv(1024).decode('utf-8'))  # Registration result
    client_socket.close()
    exit()

elif choice == "login":
    print(client_socket.recv(1024).decode('utf-8'))  # Enter username
    username = input("> ").strip()
    client_socket.sendall(username.encode('utf-8'))

    print(client_socket.recv(1024).decode('utf-8'))  # Enter password
    password = input("> ").strip()
    client_socket.sendall(password.encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    if "Invalid" in response:
        client_socket.close()
        exit()

else:
    client_socket.close()
    exit()

def play_notification():
    if sound_enabled:
        winsound.MessageBeep()

def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024).decode('utf-8')
            if response.strip():
                print(response)
                play_notification()
        except:
            break

receive_thread = threading.Thread(target=receive_messages, daemon=True)
receive_thread.start()

while True:
    message = input().strip()

    if message.lower() == "/mute":
        sound_enabled = False
        print("[Sound muted]")
        continue

    if message.lower() == "/unmute":
        sound_enabled = True
        print("[Sound unmuted]")
        continue

    if message.lower() == "exit":
        break

    client_socket.sendall(message.encode('utf-8'))

client_socket.close()
print("Disconnected from server.")
