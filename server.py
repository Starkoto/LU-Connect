import socket
import threading

HOST = '0.0.0.0'
PORT = 12345
MAX_CONNECTIONS = 3

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(MAX_CONNECTIONS)

semaphore = threading.Semaphore(MAX_CONNECTIONS)
clients = []

print(f"Server listening on {HOST}:{PORT}")

def handle_client(client_socket, client_address):
    with semaphore:
        print(f"Connection from {client_address} established.")
        clients.append(client_socket)
        while True:
            try:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                print(f"Received from {client_address}: {data}")
                
                for client in clients:
                    if client != client_socket:
                        try:
                            client.sendall(data.encode('utf-8'))
                        except:
                            clients.remove(client)
            except ConnectionResetError:
                break
        
        print(f"Connection from {client_address} closed.")
        clients.remove(client_socket)
        client_socket.close()

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
