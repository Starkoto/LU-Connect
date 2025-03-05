import socket
import threading

# Server configuration
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 12345      # Port number

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"Server listening on {HOST}:{PORT}")

def handle_client(client_socket, client_address):
    print(f"Connection from {client_address} established.")
    while True:
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break
            print(f"Received from {client_address}: {data}")
            
            response = f"Server received: {data}"
            client_socket.sendall(response.encode('utf-8'))
        except ConnectionResetError:
            break
    
    print(f"Connection from {client_address} closed.")
    client_socket.close()

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
