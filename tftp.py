"""
TFTP client and server implementation.
Copyright (C) 2025 Alexander McColm

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

tftp.py: client and server class definitions
"""

import os
import select
import socket
from threading import Thread

MODES = ["netascii", "octet", "mail"]

"""
Opcodes from RFC:
 - 1, Read request (RRQ)
 - 2, Write request (WRQ)
 - 3, Data (DATA)
 - 4, Acknowledgment (ACK)
 - 5, Error (ERROR)
"""


class Opcodes:
    """
    Enumeration of TFTP message types.
    """

    READ_REQUEST = int(1).to_bytes(2)
    WRITE_REQUEST = int(2).to_bytes(2)
    DATA = int(3).to_bytes(2)
    ACK = int(4).to_bytes(2)
    ERROR = int(5).to_bytes(2)


def create_connection_packet(message_type: str, filename: str, mode: str = "octet"):
    """
    Creates a formatted connection packet ready to send through UDP.
    """

    if message_type not in set(["r", "w"]):
        raise ValueError('Type should be "r" or "w".')

    if mode not in MODES:
        raise ValueError(f"Mode should be one of {MODES}.")

    if message_type == "r":
        opcode = Opcodes.READ_REQUEST
    elif message_type == "w":
        opcode = Opcodes.WRITE_REQUEST
    else:
        raise ValueError('Type should be "r" or "w".')

    # Start with opcode
    req = opcode + bytes(filename, "ascii") + bytes(1) + bytes(mode, "ascii") + bytes(1)

    return req


def create_data_packet(block_number: int, data: bytes):
    """
    Creates a formatted data packet ready to send through UDP.
    """
    if len(data) > 512:
        raise ValueError(
            "Data packets' contents should be strictly [0, 512] bytes in length."
        )

    if block_number < 0 or block_number >= 512:
        raise ValueError(
            "Block numbers should be in range [0, 511]; caller to handle overflow"
        )

    pkt = Opcodes.DATA
    pkt += block_number.to_bytes(2)
    pkt += data

    return pkt


def create_ack_packet(block_number: int):
    """
    Creates a formatted acknowledgement packet ready to send through UDP.
    """
    if block_number < 0 or block_number >= 512:
        raise ValueError(
            "Block numbers should be in range [0, 511]; caller to handle overflow"
        )

    ack = Opcodes.ACK
    ack += block_number.to_bytes(2)

    return ack


class ErrorCodes:
    """
    Enumeration of TFTP error types.
    """

    NOT_DEFINED = int(0).to_bytes(2)
    FILE_NOT_FOUND = int(1).to_bytes(2)
    ACCESS_VIOLATION = int(2).to_bytes(2)
    DISK_FULL = int(3).to_bytes(2)
    ILLEGAL_OPERATION = int(4).to_bytes(2)
    UNKNOWN_TID = int(5).to_bytes(2)
    FILE_EXISTS = int(6).to_bytes(2)
    NO_SUCH_USER = int(7).to_bytes(2)


def create_error_packet(code: bytes, error_message: str = ""):
    """
    Creates a formatted data packet ready to send through UDP.
    """

    if code not in [x.to_bytes(2) for x in range(0, 7 + 1)]:
        raise ValueError(
            "Error code should be a number in the range [1,7] represnted as 2 bytes."
        )

    err = Opcodes.ERROR
    err += code
    err += bytes(error_message, "ascii")
    err += bytes(1)  # one byte, value is zero

    return err


# The "known port" the server is initially contacted on.
# The RFC specifies 69, but if we use a port above 1000
# then we don't need admin permissions.
# KNOWN_PORT = 69
KNOWN_PORT = 11111
DOWNLOAD_DIR = "downloaded/"
UPLOAD_DIR = "share/"
OPERATION_TIMEOUT = 0.5
OPERATION_ATTEMPTS = 5
MAX_MESSAGE_LEN = 516

class Client:
    """
    TFTP client. Keeps track of connection state such as current block num and packet to retransmit.
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("localhost", 0))

        # This is the source port or source TID we will put in datagrams
        self.source_port = self.sock.getsockname()[1]

        self.destination_address = None
        self.destination_port = None
        self.block_num = None
        self.buffer = None
        self.multi_block = False

    def __del__(self):
        self.sock.close()

    def request_connection(self, request_type, address, filename):
        """
        Makes a write request (WRQ) or read request (RRQ) (decided by `request_type`) to the server
        located at `address`.
        """
        req = create_connection_packet(request_type, filename)

        self.sock.sendto(req, (address, KNOWN_PORT))
        self.destination_address = address

    def request_read(self, address, filename):
        """
        Makes a read request to `address`. Return True if accepted.
        """
        self.request_connection("r", address, filename)
        self.buffer = bytes(0)
        self.block_num = 0

        # Receive initial packet
        packet, (server_address, server_port) = self.sock.recvfrom(MAX_MESSAGE_LEN)

        # TODO: Check for errors in block 0

        # If the packet is full length, this will be a multi-block transfer
        if len(packet) == 516:
            self.multi_block = True

        self.buffer += packet[4:]
        self.block_num += 1

        self.destination_address = server_address
        self.destination_port = server_port

        # Acknowledge packet
        ack = create_ack_packet(self.block_num)
        self.sock.sendto(ack, (server_address, server_port))

        return True

    def request_write(self, address, filename):
        """
        Makes a write request to `address`. Return True if accepted.
        """
        # We will be expecting ACK for block 0
        self.block_num = 0

        while True:
            self.request_connection("w", address, filename)

            # Raises IOErrors for errors or timeout
            blk, (self.destination_address, self.destination_port) = self.receive_ack()

            # If the proper ack received, blk is now 1
            if blk == 1:
                break
            raise ValueError("WRQ failed")

        # Ready for first real packet
        if self.block_num != 1:
            raise IOError(f"Block num {self.block_num} not 1 after receiving ack 0")

        return True

    def receive_ack(self):
        """
        Receives acknowledgement or raises exception within set timeout.
        Assumes block num set at point of call, increments it if
        acknowledgment successfully received. Returns
        (new block num, (server addr, server port)) for success, raises
        exceptions for various types of failures.
        """
        while True:
            # Assume blocknum is set at point of call.
            if self.block_num is None:
                raise IOError("Block number was not set before receiveAck called")

            # Wait for an ack block for current blocknum.
            # Use select with specified timeout.
            # Raise IOError for timeout
            r = select.select([self.sock], [], [], OPERATION_TIMEOUT)[0]

            # Nothing ready to read within time => timeout
            if r == []:
                raise IOError("No ack received in timeout")

            # Get actual packet and check contents
            payload, (server_address, server_port) = self.sock.recvfrom(MAX_MESSAGE_LEN)

            # TODO: Abort transfer if error packet received

            # print(f'Have dest port {self.destination_port},'
            # ' Received packet from {server_port}, {payload[:50]}')

            if self.block_num == 0:
                self.destination_port = server_port

            # wrong TID => send error packet
            if server_port != self.destination_port:
                self.sock.sendto(
                    create_error_packet(ErrorCodes.UNKNOWN_TID),
                    (server_address, server_port),
                )
                continue

            # Handle payload nt being an ACK packet of expected block num
            if payload == create_ack_packet(self.block_num):
                self.block_num += 1
                return (self.block_num, (server_address, server_port))

            raise IOError(
                f"Received something other than expected ACK {self.block_num}"
            )

    def receive(self):
        """
        After making a read request (RRQ) and receiving block 0 this function
        is called to complete the transmission if there are >=2 blocks.
        """

        # Else loop until rest are received
        while True:
            # Receive packet
            packet, (server_address, server_port) = self.sock.recvfrom(MAX_MESSAGE_LEN)

            if self.destination_port is None:
                self.destination_port = server_port

            self.buffer += packet[4:]
            self.block_num += 1

            # TODO: Send error if packet has wrong source port!
            # TODO: Any other error handling

            # Acknowledge packet
            ack = create_ack_packet(self.block_num)
            self.sock.sendto(ack, (server_address, server_port))

            # We are done if the payload size is less than 512 bytes
            if len(packet) < 512:
                break

    def get_file(self, address, filename):
        """
        Handles entire process of getting a file from a remote host with TFTP.
        One of two entry points to the client, the other being sendFile.
        """

        # Make a read request
        self.request_read(address, filename)

        # Receive the file buffer (first packet is block 0 which serves as acknowledgment)
        if self.multi_block:
            self.receive()

        # Save the file
        with open(DOWNLOAD_DIR + filename, "+w", encoding="utf8") as file:
            file.write(str(self.buffer, encoding="utf8"))

        return True

    def send(self, buffer):
        """
        After a write request (WRQ) is made this function is called with
        a byte buffer to send to the destination this client is connected to.
        """
        sent = 0
        to_send = len(buffer)

        while sent < to_send:
            # Create a block
            datablock = create_data_packet(self.block_num, buffer[:512])

            # Attempt to send this block OPERATION_ATTEMPTS times
            block_attempts = 0

            while block_attempts < OPERATION_ATTEMPTS:
                self.sock.sendto(
                    datablock, (self.destination_address, self.destination_port)
                )

                sent += len(buffer[:512])
                buffer = buffer[512:]

                # Await acknowledgment

                blk = self.receive_ack()[0]
                if blk == self.block_num:
                    break
                raise IOError(
                    f"Wrong ack received! Expected {self.block_num} and got {blk}"
                )

    def send_file(self, address, filename):
        """
        Handles entire process of sending a file to remote host with TFTP.
        One of two entry points to the client, the other being getFile.
        Returns success of file transfer.
        """
        # Load the file into a byte buffer
        buf = None

        if not os.path.isfile(UPLOAD_DIR + filename):
            return False

        with open(UPLOAD_DIR + filename, "r+", encoding="utf8") as file:
            buf = bytes(file.read(), encoding="utf8")

        # Make a write request
        self.request_write(address, filename)

        # Send the buffer
        try:
            self.send(buf)
            return True
        except IOError:
            return False


class Server:
    """
    TFTP server. Listens for connections and handles them in a new thread.
    """

    def __init__(self):
        # print('server: creating listener')
        self.listener_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listener_sock.bind(("localhost", KNOWN_PORT))

        self.destination_address = None
        self.destination_port = None
        self.block_num = None

        # If a quota is set, the server will handle `quota` transactions then quit.
        self.quota = None
        self.thread_pool = []
        self.last_block = None

    def __del__(self):
        self.listener_sock.close()
        # for t in self.thread_pool:
            # t.join()

    def listen(self):
        """
        Waits for incoming transfer requests, handling them in a separate thread.
        """
        served = 0
        
        while True:
            # print('server: listening for requests')

            if self.quota and served == self.quota:
                # print('server: quitting listening for quota')
                return
            # else:
                # print(f'served: {served}, quota: {self.quota}, quota is none: {self.quota is None}')
            
            payload, (client_address, client_port) = self.listener_sock.recvfrom(MAX_MESSAGE_LEN)

            type = payload[:2]
            # print(f'server: received request with type {type}')

            if type == b"\x00\x01":
                served += 1
                t = Thread(target=self.send_file, args=[client_address, client_port, payload])
                t.start()
                self.thread_pool.append(t)
            elif type == b"\x00\x02":
                served += 1
                t = Thread(target=self.receive_file, args=[client_address, client_port, payload])
                t.start()
                self.thread_pool.append(t)
            else:
                print('server: didn\'t recognize request type')

    def receive_file(self, client_address, client_port, request_packet):
        """
        Responds to a WRQ from a client, completes the transaction and returns.
        """
        block_num = 0

    def send_file(self, client_address, client_port, request_packet):
        """
        Responds to a RRQ from a client, completes the transaction and returns.
        """
        block_num = 0

        # find 0 byte that delimits filename
        null_pos = request_packet[2:].find(b"\x00") + 2
        filename = request_packet[2:null_pos]
        # print(f'sending file {filename}')

        # open file into a buffer
        buf = None
        try:
            with open(filename, 'r') as file:
                buf = bytes(file.read(), encoding='utf8')
        except FileNotFoundError:
            print('TODO: implement filenotfound')

        # create a server socket specific to the transaction served by this thread
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('localhost', 0))


        sent = 0
        to_send = len(buf)
        while sent < to_send:
            # Create data packet
            data_packet = create_data_packet(block_num, buf[:512])

            # Send to client
            sock.sendto(data_packet, (client_address, client_port))

            # print(f'server: sent data packet "{data_packet}"')

            # Await acknowledgment

            # Update counter
            sent += len(data_packet[4:])

        sock.close()