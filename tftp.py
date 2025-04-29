'''
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

    main.py: entry point for application
'''
import select
import socket

MODES = [
    'netascii',
    'octet',
    'mail'
]

'''
Opcodes from RFC:
 - 1, Read request (RRQ)
 - 2, Write request (WRQ)
 - 3, Data (DATA)
 - 4, Acknowledgment (ACK)
 - 5, Error (ERROR)
'''
class Opcodes:
    READ_REQUEST = int(1).to_bytes(2)
    WRITE_REQUEST = int(2).to_bytes(2)
    DATA = int(3).to_bytes(2)
    ACK = int(4).to_bytes(2)
    ERROR = int(5).to_bytes(2)

def createConnectionPacket(type: str, filename: str, mode: str = 'octet'):
    '''
    Creates a formatted connection packet ready to send through UDP.
    '''

    if type != 'r' and type != 'w':
        raise ValueError('Type should be "r" or "w".')

    if mode not in MODES:
        raise ValueError(f'Mode should be one of {MODES}.')

    if type == 'r':
        opcode = Opcodes.READ_REQUEST
    elif type == 'w':
        opcode = Opcodes.WRITE_REQUEST

    # Start with opcode
    req = opcode + \
        bytes(filename, 'ascii') + \
        bytes(1) + \
        bytes(mode, 'ascii') + \
        bytes(1)

    return req

def createDataPacket(blockNumber: int, data: bytes):
    '''
    Creates a formatted data packet ready to send through UDP.
    '''
    if len(data) > 512:
        raise ValueError('Data packets\' contents should be strictly [0, 512] bytes in length.')

    if blockNumber < 0 or blockNumber >= 512:
        raise ValueError('Block numbers should be in the range [0, 511]; caller should handle overflow')

    pkt = Opcodes.DATA
    pkt += blockNumber.to_bytes(2)
    pkt += data

    return pkt

def createAckPacket(blockNumber: int):
    '''
    Creates a formatted acknowledgement packet ready to send through UDP.
    '''
    if blockNumber < 0 or blockNumber >= 512:
        raise ValueError('Block numbers should be in the range [0, 511]; caller should handle overflow')

    ack = Opcodes.ACK
    ack += blockNumber.to_bytes(2)

    return ack

class ErrorCodes:
    NOT_DEFINED = int(0).to_bytes(2)
    FILE_NOT_FOUND = int(1).to_bytes(2)
    ACCESS_VIOLATION = int(2).to_bytes(2)
    DISK_FULL = int(3).to_bytes(2)
    ILLEGAL_OPERATION = int(4).to_bytes(2)
    UNKNOWN_TID = int(5).to_bytes(2)
    FILE_EXISTS = int(6).to_bytes(2)
    NO_SUCH_USER = int(7).to_bytes(2)

def createErrorPacket(code: bytes, errorMessage: str = ''):
    '''
    Creates a formatted data packet ready to send through UDP.
    '''

    if code not in [ x.to_bytes(2) for x in range(0, 7+1) ]:
        raise ValueError('Error code should be a number in the range [1,7] represnted as 2 bytes.')

    err = Opcodes.ERROR
    err += code
    err += bytes(errorMessage, 'ascii')
    err += bytes(1) # one byte, value is zero

    return err

# The "known port" the server is initially contacted on.
# The RFC specifies 69, but if we use a port above 1000
# then we don't need admin permissions.
# KNOWN_PORT = 69
KNOWN_PORT = 11111
DOWNLOAD_DIR = 'downloaded/'
UPLOAD_DIR = 'share/'
OPERATION_TIMEOUT = 0.5
OPERATION_ATTEMPTS = 5

class Client():
    '''
    TFTP client. Keeps track of connection state such as current block num and packet to retransmit.
    '''

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost', 0))

        # This is the source port or source TID we will put in datagrams
        self.sourcePort = self.sock.getsockname()[1]

        # set timeout for all socket operations
        # TODO: figure out how to implement timeouts properly!
        # This closes the socket globally after the timeout
        # self.sock.settimeout(OPERATION_TIMEOUT)

        # Connection state
        self.requestAccepted = False
        self.blockNum = None

    def __del__(self):
        self.sock.close()

    def requestConnection(self, type, address, filename):
        req = createConnectionPacket(type, filename)

        self.sock.sendto(req, (address, KNOWN_PORT))
        self.destinationAddress = address

    def requestRead(self, address, filename):
        self.requestConnection('r', address, filename)

    def receiveAck(self):
        '''
        Receives acknowledgement or raises exception within set timeout.
        Assumes block num set at point of call, increments it if 
        acknowledgment successfully received. Returns 
        (new block num, (server addr, server port)) for success, raises 
        exceptions for various types of failures.
        '''
        
        # Assume blocknum is set at point of call.
        if self.blockNum is None:
            raise IOError('Block number was not set before receiveAck called')
        
        # Wait for an ack block for current blocknum.
        # Use select with specified timeout.
        # Raise IOError for timeout
        r, w, x = select.select([self.sock], [], [], OPERATION_TIMEOUT)
        
        # print(f'r: {r} w: {w} x: {x}')
        
        # Nothing ready to read within time => timeout
        if r == []:
            raise IOError('No ack received in timeout')
        
        # Check FD
        if r[0].fileno != self.sock.fileno:
            raise ValueError(f' readable: {r} first: {r[0]} Different sock ready to read')
        
        # Get actual packet and check contents
        payload, (serverAddress, serverPort) = self.sock.recvfrom(1024)

        # TODO: wrong TID => send error packet

        # Handle payload nt being an ACK 0 packet
        if payload == createAckPacket(self.blockNum):
            self.blockNum += 1
            return (self.blockNum, (serverAddress, serverPort))
        else:
            raise IOError(f'Wrong ack received')

    def requestWrite(self, address, filename):
        # We will be expecting ACK for block 0
        self.blockNum = 0

        requestAttempts = 0
        while requestAttempts < OPERATION_ATTEMPTS:
            self.requestConnection('w', address, filename)
            
            try:
                blk, (self.destinationAddress, self.destinationPort) = self.receiveAck()
                
                # If proper ack received:
                if blk:
                    break
            # TODO: Handle exceptions properly!
            except IOError:
                pass
            except ValueError:
                pass
            requestAttempts += 1

        # Ready for first real packet
        if self.blockNum != 1:
            raise IOError('Block num was not 1 after receiving ack 0 => WRQ not accepted')

    def receive(self):
        '''
        After making a read request (RRQ) this function is called to
        initiate and complete the transmission.
        '''

        buffer = bytes(0)
        self.blockNum = 0

        # Receive initial packet
        packet, (serverAddress, serverPort) = self.sock.recvfrom(1024)
        buffer += packet[4:]
        self.blockNum += 1

        self.destinationAddress = serverAddress
        self.destinationPort = serverPort

        # Acknowledge packet
        ack = createAckPacket(self.blockNum)
        self.sock.sendto(ack, (serverAddress, serverPort))


        # Return now if initial packet is also ending packet
        if len(packet) < 512:
            return buffer

        # Else loop until rest are received
        while True:
            # Receive packet
            packet, (serverAddress, serverPort) = self.sock.recvfrom(1024)

            if self.destinationPort is None:
                self.destinationPort = serverPort

            buffer += packet[4:]
            self.blockNum += 1

            # TODO: Send error if packet has wrong source port!
            # TODO: Any other error handling

            # Acknowledge packet
            ack = createAckPacket(self.blockNum)
            self.sock.sendto(ack, (serverAddress, serverPort))

            # We are done if the payload size is less than 512 bytes
            if len(packet) < 512:
                break
        return buffer

    def getFile(self, address, filename):
        '''
        Handles entire process of getting a file from a remote host with TFTP.
        One of two entry points to the client, the other being sendFile.
        '''

        # Make a read request
        self.requestRead(address, filename)

        # Receive the file buffer (first packet is ACK)
        fileBuffer = self.receive()

        # Save the file
        with open(DOWNLOAD_DIR + filename, '+w') as file:
            file.write(str(fileBuffer, encoding='utf8'))

    def send(self, buffer):
        '''
        After a write request (WRQ) is made this function is called with
        a byte buffer to send to the destination this client is connected to.
        '''
        sent = 0
        toSend = len(buffer)

        while sent < toSend:
            # Create a block
            datablock = createDataPacket(self.blockNum, buffer[:512])

            # Attempt to send this block OPERATION_ATTEMPTS times
            blockAttempts = 0
            sent = False
            
            while blockAttempts < OPERATION_ATTEMPTS and not sent:
                # TODO: Send blocks and wait for timeout UNTIL acknowledgement is received
                self.sock.sendto(datablock, (self.destinationAddress, self.destinationPort))

                sent += len(buffer[:512])
                buffer = buffer[512:]

                # TODO: Handle potential erroneous ACKs or error packets
                # Await acknowledgment
                ack, (serverAddress, serverPort) = self.sock.recvfrom(1024)
                
                # if ack == createAckPacket(self.blockNum):
                #     sent = True
                #     print(f'\n. Correct ACK received! should be {self.blockNum}, was {ack}')
                # else:
                #     raise IOError(f'\nx incorrect ACK received! should be {self.blockNum}, was {ack}')
                self.blockNum += 1             
                


    def sendFile(self, address, filename):
        '''
        Handles entire process of sending a file to remote host with TFTP.
        One of two entry points to the client, the other being getFile.
        '''
        # Load the file into a byte buffer
        buf = None

        with open(UPLOAD_DIR + filename, 'r+') as file:
            buf = bytes(file.read(), encoding='utf8')

        # Make a write request
        self.requestWrite(address, filename)

        # Send the buffer
        self.send(buf)