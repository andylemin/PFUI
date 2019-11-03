#!/usr/bin/env python3

import socket
import sys

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('localhost', 10000)
message = b'A' * 800

try:

    # Send data
    print('Sending {} {} {!r}'.format(len(message), sys.getsizeof(message), message))
    try:
        sent = sock.sendto(message, server_address)
    except Exception as e:
        print("Error: {}".format(e))
    else:
        print('Sent: {}'.format(sent))

        # Receive response
        print('Waiting to receive')
        data, server = sock.recvfrom(4096)
        print('Received {} {} {!r}'.format(len(data), sys.getsizeof(data), data))

finally:
    print('closing socket')
    sock.close()


