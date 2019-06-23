import socket
import argparse
import time

def build_msg(size):
    msg = ''
    for i in range(size):
        msg+=chr(ord('a') + (i)%26)

    return msg

def send(host, port, rate, size, time_limit):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (host, port)

    init = time.time()
    msg = build_msg(size)
    while time.time() - init < time_limit:
        
        udp_sock.sendto(msg, dest)
        time.sleep(float(size)/float(rate))

    udp_sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UDP spammer client')
    parser.add_argument('-a', '--host', help='IP address of the receiver',
                        type=str, action="store", required=True)
    parser.add_argument('-p', '--port', help='Port used by the receiver',
                        type=int, action="store", required=True)
    parser.add_argument('-r', '--rate', help='Rate to transmit in bytes/s', 
                        type=int, action="store", required=True)
    parser.add_argument('-s', '--size', help='Size of the message to send in bytes', 
                        type=int, action="store", required=True)
    parser.add_argument('-t', '--time', help='Time in seconds to send', 
                        type=int, action="store", required=True)
    args = parser.parse_args()
    send(args.host, args.port, args.rate, args.size, args.time)