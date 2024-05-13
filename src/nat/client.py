import socket
import sys
import threading

exit_event = threading.Event()

def receive_messages(client_socket):
    while not exit_event.is_set():
        try:
            data= client_socket.recv(1024)
            if not data:
                break
            print(data.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def main():
    while True:
        # ip = input("Enter IP address (or 'exit' to quit): ")
        # if ip.lower() == 'ex':
        #     break
        # port = input("Enter port number: ")
        ip="140.113.0.1"
        port=80
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((ip, int(port)))
            
            print(f"Connected to {ip}:{port}")

            receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
            receive_thread.start()

            while True:
                message = input("Enter message to send (or 'ex' to disconnect): ")
                if message.lower() == 'ex':
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()  
                    print("Connection closed.")
                    break
                else:
                    client_socket.send(message.encode('utf-8'))

        except Exception as e:
            print(f"Error: {e}")
        finally:
            print("Closing socket...")
            exit_event.set()
            client_socket.close()

if __name__ == "__main__":
    main()
