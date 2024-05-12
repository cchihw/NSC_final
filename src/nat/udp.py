import socket
import sys
import threading

def receive_messages(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"\nReceived message from {addr}: {data.decode()}")

def send_messages(sock, dest_host, dest_port):
    message = input("Enter message to send: ")
    sock.sendto(message.encode(), (dest_host, dest_port))

def main():
    if len(sys.argv) != 2:
        print("Usage: python udp.py <host_number>")
        sys.exit(1)
    
    host_number = int(sys.argv[1])
    if(host_number==1):
        host = "10.0.1.1"
        port= 8080
    elif host_number==2:
        host= "10.0.1.2"
        port= 8080
    elif host_number==3:
        host="140.113.100.100"
        port= 8080
    elif host_number==4:
        host="140.113.200.200"
        port=8080

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        print(f"UDP socket bound to {host}:{port}")
        sender=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        receive_thread.start()

        while True:
            dest_ip= input("Enter destination IP address: ")
            dest_port = input("Enter destination port: ")
            send_messages(sock,dest_ip, int(dest_port))

    except Exception as e:
        print("An error occurred:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()