import socket
import threading

HOST = '0.0.0.0'
PORT = 12345
MAX_CONNECTIONS = 3

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(MAX_CONNECTIONS)

semaphore = threading.Semaphore(MAX_CONNECTIONS)
clients = {}  # Dictionary to store clients {username: socket}

print(f"Server listening on {HOST}:{PORT}")

def handle_client(client_socket, client_address):
    with semaphore:
        try:
            client_socket.sendall("Enter your username: ".encode('utf-8'))
            username = client_socket.recv(1024).decode('utf-8').strip()
            
            if username in clients:
                client_socket.sendall("Username already taken. Disconnecting...\n".encode('utf-8'))
                client_socket.close()
                return

            clients[username] = client_socket
            print(f"User '{username}' connected from {client_address}.")
            client_socket.sendall(f"Welcome, {username}! Type @recipient message to send a message.\n".encode('utf-8'))

            while True:
                data = client_socket.recv(1024).decode('utf-8').strip()
                if not data:
                    break

                print(f"Received from {username}: {data}")

                if data.startswith("@"):
                    recipient, message = data.split(" ", 1)
                    recipient = recipient[1:]

                    if recipient in clients:
                        try:
                            clients[recipient].sendall(f"From {username}: {message}\n".encode('utf-8'))
                        except:
                            del clients[recipient]
                    else:
                        client_socket.sendall("Recipient not found.\n".encode('utf-8'))
                else:
                    client_socket.sendall("Invalid format. Use @username message.\n".encode('utf-8'))

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
