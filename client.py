import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

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

def receive_messages():
    while True:
        try:
            response = client_socket.recv(1024).decode('utf-8')
            if not response:
                break
            print(f"{response}")
        except:
            break

receive_thread = threading.Thread(target=receive_messages, daemon=True)
receive_thread.start()

while True:
    message = input()
    if message.lower() == 'exit':
        break
    client_socket.sendall(message.encode('utf-8'))

client_socket.close()
print("Disconnected from server.")
