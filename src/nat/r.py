import socket
import threading

exit_event = threading.Event()

def receive_messages(client_socket, client_address):
    while not exit_event.is_set():
        try:
            data = client_socket.recv(1024)
            if data:
                message = data.decode('utf-8')
                print(f"Received message from {client_address}: {message}")
                if message.strip().lower() == 'exit':
                    print(f"Received 'exit' command from {client_address}, closing connection...")
                    break
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()
    print(f"Connection with {client_address} closed.")

def main():
    # Create a TCP/IP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set REUSEADDR option
    s.bind(('140.113.100.100', 12345))
    s.listen(5)
    print("Waiting for a connection...")

    threads = []
    try:
        while True:
            client_socket, client_address = s.accept()
            print(f"Connection from {client_address}")
            t = threading.Thread(target=receive_messages, args=(client_socket, client_address))
            t.start()
            threads.append(t)

    except KeyboardInterrupt:
        print("Received keyboard interrupt, closing server...")
        for t in threads:
            t.join()  # Wait for all threads to finish
        exit_event.set()
        s.close()
        print("Server closed.")


if __name__ == "__main__":
    main()
