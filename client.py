import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

print("Connected to server. Type 'exit' to quit.")

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
