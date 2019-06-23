import socket
import argparse
import time

def receive(port, size, mayprint):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    orig = ('', port)

    udp_sock.bind(orig)
    while True:
        msg, client = udp_sock.recvfrom(size) 
        if mayprint:
            print 'Received message from client ' + str(client) + ':\n' + str(msg) 
    udp_sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP spammer client')
    parser.add_argument('-p', '--port', help='Port used by the receiver',
                        type=int, action="store", required=True)
    parser.add_argument('-s', '--size', help='Size of the messages to receive in bytes', 
                        type=int, action="store", required=True)
    parser.add_argument('-m', '--mayprint', help='determine whether the message should be printed or not (type False or True)',
                        type=bool, action="store", required=False, default=False)
    args = parser.parse_args()
    receive(args.port, args.size, args.mayprint)