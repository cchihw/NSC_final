# NSC Final Lab - NAT Implementation using P4 language with bmv2 switch
## Introduction:
This project is a simple implementation of Layer 4 port based NAT (Network Address Translation) using P4 language with bmv2 switch. The environment will simulate a scheme with a internal network and outer network, then any packet with L4 TCP/UDP header will be translated to the outer/internal network with a public IP address using the src/dst transport layer port.
## Environment:
- Ubuntu: 20.04
- Mininet: 2.3.1b4
- bmv2: Connot find the version.
- p4c: 1.2.4.2
## Install Guide:
Using the repo P4-guide to install the environment, the installation script I used is install-p4dev-v5.sh, but it must running in Ubuntu 20.04, you can find it in the bin folder. Using other version installation script or ubuntu may cause a longer installing time or dependency problem. After the installation, all the environment including mininet, bmv2, p4c, and other necessary tools will be installed in the system.
### Repo link:
https://github.com/jafingerhut/p4-guide.git
### Installation command:
```
$ git clone https://github.com/jafingerhut/p4-guide.git
$ cd bin
$ bash install-p4dev-v5.sh
```
## Run Code
Using command "make" to run the code, it will compile the p4 code and start the mininet environment. Any compile error will be shown in the terminal, and the mininet environment will be started if the code is compiled successfully.
```
$ make
```
## Clean Running log
This command will delete all the logs during the running time, so if you want to debug using the log, please do not use this command, or using this after you finish debugging.
```
$ clean
```

## Network Topology
The topology is a network with 4 hosts and 1 switch, I simply divide the network into three parts, internal network h1 and h2, two outer network h3 and h4, three networks are connected by the switch s1. The MAC address and IP address are shown in the following table:
![Network Topology](pic/topo.jpeg)
### Network 1:
- h1 and h2, with MAC address prefix `08:00:00:01:{host_number}` and IP prefix `10.0.1.{host_number}/24`
- Default gateway: `10.0.1.10` at eth0 to switch s1
- Using public IP address: `140.113.0.1`
### Network 2:
- h3 with MAC address `08:00:00:03:03` and IP address `140.113.100.100/24`
- Default gateway: `140.113.100.50` at eth0 to switch s1
### Network 3:
- h4 with MAC address `08:00:00:04:04` and IP address `140.113.200.200/24`
- Default gateway: `140.113.200.50` at eth0 to switch s1

| Host |    MAC Address    |     IP Address    |
|------|-------------------|-------------------|
|  h1  | 00:00:00:00:01:01 |   10.0.1.1/24     |
|  h2  | 00:00:00:00:01:02 |   10.0.1.2/24     |
|  h3  | 00:00:00:00:03:03 | 140.113.100.100/24|
|  h4  | 00:00:00:00:04:04 | 140.113.200.200/24|
### Test Command and Program:
Once you finish set up the environment, you can use the following command to test the network:
```
mininet> pingall
```
This command will help you to inspect the network connection, if the network is connected successfully, you can see the folling result:
```
*** Ping: testing ping reachability
h1 -> h2 h3 h4 
h2 -> h1 h3 h4 
h3 -> h1 h2 h4 
h4 -> h1 h2 h3 
*** Results: 0% dropped (12/12 received)
```
If the result is same as above, you can use the following command to test the NAT function, The test program can be classified into three parts:
1. TCP connection from two host in same internal network to the outer network host.

    This test will simulate if two internal hosts are using the same program and trying to connect to a same outer network host, the NAT function will assign an outer port as the source port using in public network and record it accoding to the internal IP and port.<br>
    Test content:
    - s.py 'n' or 'b':TCP sender program, it will send a message to the receiver program, argument 'n' for not binding the port, 'b' for binding the source port to 8888.
    - r.py: The TCP receiver program, it will listen to the port 12345 and print the received message.
    
    Test flow:<br>
    After starting the mininet environment:
    ```
    mininet> xterm h1 h2 h3
    ```
    At terminal h3:
    ```
    h1> python3 r.py
    ```
    At terminal h1,h2:
    ```
    h1> python3 s.py n or b
    s.py> 140.113.100.100
    s.py> 12345
    ```
    After the program start, you can see the TCP connection is built successfully, and the corresponding srouce port after the NAT is shown in h3's terminal.
    If you use the 'b' argument both at h1 and h2, you can see the both h1 and h2's source port is 8888 in wireshark, but at h3's terminal, the source port is different, which means the NAT function is working.
2. Test the UDP connection from an internal network host to an outer network host.
    Test content:
    - udp.py 'host number': The UDP sender program, it will send a message to the receiver program, the argument is the corresponding starter host number, the program will automatically bind the sender and receiver thread to the IP:port at `{host_IP:8080}`
    Test flow:<br>
    ```    
    mininet> xterm h1 h3
    ```
    At terminal h1:
    ```
    h1> python3 udp.py 1
    udp.py> 140.113.100.100
    udp.py> 8080
    udp.py> Hello from h1.
    ```
    At terminal h3:
    ```
    h3> python3 udp.py 3
    udp.py> 140.113.0.1
    udp.py> {the corresponding port shown in h3's terminal}
    udp.py> Hello from h3.
    ```
    The test flow is similar to the TCP test, h1 first start a udp connection at port 8080, the send a message to h3, after the NAT, the source port 8080 will be translated to another port, and the message will be received by h3.

    If h3 reply a message to h1 using the source port after NAT, the message will be received by h1, which means the NAT function can actually translate the outer port to the original internal port 8080 and internal IP h1.
3. Test the Port forwarding function from the outer network host to the internal network host.
    
    Test content:
    - server.py: The server program, it will listen to the port 80 to simulate the http web server.
    - s.py: The client program, it will build a connection to the server program.

    Test flow:<br>
    ```
    mininet> xterm h1 h3
    ```
    At terminal h1:
    ```
    h1> python3 server.py
    ```
    At terminal h3:
    ```
    h3> python3 s.py
    s.py> 140.113.0.1
    s.py> 80
    ```
    After the command is executed, you can see the host h3 will periodically receive a message from h1, which means the port forwarding function is working.
