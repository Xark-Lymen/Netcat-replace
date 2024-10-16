## Below is the python code to recreate/replace netcat for enterprises usage.

```
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading 


def execute(cmd):
    cmd= cmd.strip()
    if not cmd:
        return
    output= subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()

class NetCat:
    def __init__(self, args, buffer=None):
        self.args=args
        self.buffer=buffer
        self.socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        def run(self):
            if self.args.listen():
                self.listen()
            else:
                self.send()



def send(self):
    self.socket.connect((self.args.target, self.args.port))
    if self.buffer:
        self.socket.send(self.buffer)

    try:
        while True:
            recv_len=1 
            response= ''
            while recv_len:
                data=self.socket.recv(4096)
                recv_len= len(data)
                response += data.decode()
                if recv_len < 4096:
                    break
            if response:
                print(response)
                buffer= input('> ')
                buffer += '\n'
                self.socket.send(buffer.encode())
    except KeyboardInterrupt:
        print('User Terminated.')
        self.socket.close()
        sys.exit()



def listen(self):
    self.socket.bind((self.args.target, self.args.port))
    self.socket.listen(5)
    while True:
        client_socket, _= self.socket.accept()
        client_thread= threading.Thread(target=self.handle, args=(client_socket,))
        client_thread.start()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example: 2 netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload to file
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat/etc/passwd\" # execute commandecho 'ABC' | ./
            netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
            netcat.py -t 192.168.1.108 -p 5555 # connect to server'''))
    parser.add_argument('-c', '--command',
    action='store_true', help='command shell') 
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen',
    action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int,
    default=5555, help='specified port')
    parser.add_argument('-t', '--target',
    default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()
    nc = NetCat(args, buffer.encode())
    nc.run()


def handle(self,client_socket):
    if self.args.execute:
        output=execute(self.args.execute)
        client_socket.send(output.encode())

    elif self.args.upload:
        file_buffer=b''
        while True:
            data= client_socket.recv(4096)
            if data:
                file_buffer+= data 
            else:
                break
        with open(self.args.upload, 'wb') as f:
            f.write(file_buffer)
            message = f'Saved File{self.args.upload}'
            client_socket.send(message.encode())
    elif self.args.command :
        cmd_buffer=b''
        while True:
            try:
                client_socket.send(b'BHP: #> ')
                while '\n' not in cmd_buffer.decode():
                    cmd_buffer += client_socket.recv(64)
                response= execute(cmd_buffer.decode())
                if response:
                    client_socket.send(response.encode())
                cmd_buffer=b''
            except Exception as e:
                print (f'server killed {e}')
                self.socket.close()
                sys.exit()

```
## Here is a TCP proxy code for practice purpose
```
import sys
import socket
import threading


HEX_FILTER = ''.join([(len(repr(chr(i)))==3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length=16, show= True):
    if isinstance(src, bytes):
        src= src.decode()
    results =list()
    for i in range(0, len(src), length):
        word=str(src[i:i+length])
        

        printable =word.translate(HEX_FILTER)
        hexa=' '.join([f'{ord(c):02X}' for c in word])
        hexwidth=length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results
    


def receive_from(connection):
    buffer=b""
    connection.settimeout(5)
    try:
        while True:
            data= connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
    return buffer 


def request_handler(buffer):
    #Perform Packet Modifications
    return buffer 

def response_handler(buffer):
    # Perform Packet Modifications
    return buffer


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
    
    remote_buffer= response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes from localhost." % len(local_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)

            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to LocalHost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing Connections.")
            break


def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print('Problem on Bind: %r' % e)
        
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit(0)

    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(5)
    while True:
        client_socket, addr = server.accept()
        # Print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0]. addr[1])
        print(line)
        #start a thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))

        proxy_thread.start()



def main():
    if len(sys.argv[1:]) !=5:
        print("Usage: ./proxy.py [localhost][localport]", end='')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host= sys.argv[1]
    local_port= int(sys.argv[2])
    remote_host= sys.argv[3]
    remote_port= int(sys.argv[4])

    receive_first= sys.argv[5]

    if "True" in receive_first:
        receive_first= True
    else:
        receive_first= False
    
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    main()


                                                              
```
    
        
