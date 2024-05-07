import socket
from time import sleep
import threading

exit_event = threading.Event()

def server(client_socket, client_address):
    while not exit_event.is_set():
        try:
            message="Hello from server"
            client_socket.send(message.encode('utf-8'))
            sleep(2)
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
    s.bind(('10.0.1.1', 80))
    s.listen(5)
    print("Waiting for a connection...")

    threads = []
    try:
        while True:
            client_socket, client_address = s.accept()
            print(f"Connection from {client_address}")
            t = threading.Thread(target=server, args=(client_socket, client_address))
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
