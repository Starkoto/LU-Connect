import socket

HOST = '127.0.0.1'  
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

print("Connected to server. Type 'exit' to quit.")

while True:
    message = input("Enter message: ")
    if message.lower() == 'exit':
        break
    
    client_socket.sendall(message.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(f"Server response: {response}")

client_socket.close()
print("Disconnected from server.")
