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
    
    test.py: unit tests for all parts of the program
'''
# Modules from std library
from queue import Queue
import unittest
import socket
import os
from threading import Thread

# Modules from this project
import tftp


class RequestPacketCreationTests(unittest.TestCase):
    def test_bad_request_type(self):
        # There is no "x" mode, it's either 'r' or 'w'
        badCall = lambda : tftp.createConnectionPacket('x', 'x.png')
        self.assertRaises(ValueError, badCall)
    
    def test_bad_request_mode(self):
        # There is no unicode mode - this should raise an exception
        badCall = lambda : tftp.createConnectionPacket('r', 'x.png', 'unicode')
        self.assertRaises(ValueError, badCall)
    
    def test_good_write_requests(self):
        req = tftp.createConnectionPacket('w', 'document.txt')
        exp = b'\x00\x02document.txt\x00octet\x00'
        self.assertEqual(req, exp)
        
        req = tftp.createConnectionPacket('w', 'image.png', mode='netascii')
        exp = b'\x00\x02image.png\x00netascii\x00'
        self.assertEqual(req, exp)
    
    def test_good_read_requests(self):
        req = tftp.createConnectionPacket('r', 'hello.txt')
        exp = b'\x00\x01hello.txt\x00octet\x00'
        self.assertEqual(req, exp)
        
        req = tftp.createConnectionPacket('r', 'world.png', mode='netascii')
        exp = b'\x00\x01world.png\x00netascii\x00'
        self.assertEqual(req, exp)

class DataPacketCreationTests(unittest.TestCase):
    def test_bad_block_number(self):
        for badNum in [-10, -1, 1000, 2048]:
            badCall = lambda : tftp.createDataPacket(badNum, bytes(badNum))
            self.assertRaises(ValueError, badCall)

    def test_no_data_ok(self):
        pkt = tftp.createDataPacket(5, bytes(0))
        exp = b'\x00\x03\x00\x05'
        self.assertEqual(pkt, exp)
    
    def test_ok_sizes(self):
        for num in [512, 5, 17, 1, 511, 256]:
            pkt = tftp.createDataPacket(5, bytes(num))
            exp = b'\x00\x03\x00\x05' + bytes(num)
            self.assertEqual(pkt, exp)
    
    def test_encoded_bytes(self):
        # Chinese characters, full width ！ (not !), then some ascii digits
        data = bytes('大林和小林是一本很有意思的小说！ 12345678', 'utf8')
        pkt = tftp.createDataPacket(2, data)
        exp = b'\x00\x03\x00\x02' + data
        self.assertEqual(exp, pkt)

class AckPacketCreationTests(unittest.TestCase):
    def test_bad_block_number(self):
        for badNum in [-10, -1, 1000, 2048]:
            badCall = lambda : tftp.createAckPacket(badNum)
            self.assertRaises(ValueError, badCall)
    
    def test_ok_block_number(self):
        for num in [5, 17, 1, 511, 256]:
            pkt = tftp.createAckPacket(num)
            exp = b'\x00\x04' + int(num).to_bytes(2)
            self.assertEqual(pkt, exp)

class ErrorPacketCreationTests(unittest.TestCase):
    def test_bad_code(self):
        badCall = lambda : tftp.createErrorPacket(int(255).to_bytes(2), 'hella, warld!')
        self.assertRaises(ValueError, badCall)

    def test_valid_codes(self):
        for num in range(1, 7+1):
            err = tftp.createErrorPacket(num.to_bytes(2))
            exp = b'\x00\x05' + num.to_bytes(2) + bytes(1)
            
class ClientBehaviourTests(unittest.TestCase):
    def test_create_bind(self):
        client = tftp.Client()
        
        self.assertIsNotNone(client.sourcePort)
        self.assertEqual(client.sourcePort, client.sock.getsockname()[1])
    
    def test_write_request_timeout(self):
        '''
        Tests triggering a client to timeout by not sending ACK 0 to WRQ
        '''
        client = tftp.Client()
        
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        t = Thread(target=self.assertRaises, args=[IOError, lambda : client.requestWrite('127.0.0.1', 'doc.txt')])
        t.start()
        t.join(0.75)
        srv.close()
    
    def test_write_request(self):
        '''
        Tests client sending WRQ and server replying with ACK.
        '''
        client = tftp.Client()
        
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # Make a write request, put it in a thread so it can block for our response
        t = Thread(target = client.requestWrite, args=['0.0.0.0', 'doc.txt'])
        t.start()
        payload, (client_address, client_port) = srv.recvfrom(1024)
        
        # Verify what was received by the server
        self.assertEqual(tftp.createConnectionPacket('w', 'doc.txt'), payload)

        # Send the ACK from a different socket
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 12222))
        srv.sendto(tftp.createAckPacket(0), (client_address, client_port))

        # Wait for client thread to finish, so we can check state of client
        t.join(0.5)
        
        self.assertEqual(client.destinationPort, 12222)
        
        srv.close()

    def test_receive(self):
        '''
        Tests ability to receive packets and send acknowledgement.
        '''
        client = tftp.Client()
        
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))

        # requestWrite would also usually bind blockNum
        client.blockNum = 0

        # Create thread where client receives blocks
        t = Thread(target=client.receive)
        t.start()
        
        # Send 5 blocks, 4 of size 512, and then one of 511 bytes
        fullMessage = 64 * bytes('honeybee', 'utf8')
        shortMessage = fullMessage[:511]
        
        for i in range(4):
            # Send a block, receive ACK, check that it is correct
            srv.sendto(fullMessage, ('127.0.0.1', client.sourcePort))
            payload, (client_address, client_port) = srv.recvfrom(1024)
            acknowledged = int.from_bytes(payload[2:])
            self.assertEqual(acknowledged, i+1)
            
        srv.sendto(shortMessage, ('127.0.0.1', client.sourcePort))   
        payload, (client_address, client_port) = srv.recvfrom(1024)
        acknowledged = int.from_bytes(payload[2:])
        self.assertEqual(acknowledged, 5)
        
        t.join(0.5)
        
        self.assertEqual(client.blockNum, 5)
        
        srv.close()

    def test_read_request(self):
        '''
        Tests client sending RRQ and server replying with first packet.
        '''
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # Make a read request, put it in a thread so it can block for our response
        t = Thread(target = client.getFile, args=['0.0.0.0', 'doc.txt'])
        t.start()
        payload, (client_address, client_port) = srv.recvfrom(1024)
        
        # Verify what was received by the server
        self.assertEqual(tftp.createConnectionPacket('r', 'doc.txt'), payload)

        # Send one segment from a different socket
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 12223))
        
        srv.sendto(tftp.createDataPacket(1, bytes('Hello, World!', 'utf8')), (client_address, client_port))
        payload, (client_address, client_port) = srv.recvfrom(1024)
        
        # Verify what was received by the server
        self.assertEqual(tftp.createAckPacket(1), payload)
        
        t.join(0.5)
        srv.close()

    def test_send(self):
        '''
        Tests that client can send a multi-block buffer to the server properly
        '''
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # From client, make a write request, then join thread
        t = Thread(target=client.requestWrite, args=['127.0.0.1', 'honeybee.txt'])
        t.start()
        
        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(tftp.createConnectionPacket('w', 'honeybee.txt'), payload)

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 12224))
        
        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.createAckPacket(0), (client_address, client_port))
        
        t.join(0.5)
        
        # The client should have set destinationAddress and destinationPort now
        self.assertEqual(client.destinationAddress, '127.0.0.1') 
        self.assertEqual(client.destinationPort, 12224) 
        
        # Create new thread that sends blocks
        big_block = bytes('honeybee', 'utf8') * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        
        t = Thread(target=client.send, args=[buffer])
        t.start()
        
        # Receive and acknowledge blocks 1, 2, 3
        for blockNum in range(1, 3+1):
            payload, (client_address, client_port) = srv.recvfrom(1024)
            
            # Verify block number of data block
            self.assertEqual(int.from_bytes(payload[2:4]), blockNum)
            
            # Verify contents
            self.assertEqual(payload[4:], big_block)
            
            # Acknowledge data block
            srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))
        
        # Receive and acknowledge final block 4
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 4)
        self.assertEqual(payload[4:], lil_block)
        srv.sendto(tftp.createAckPacket(4), (client_address, client_port))

        t.join(0.5)
        
        srv.close()

    def test_send_file(self):
        '''
        Send a *large* multi block file from the client using the proper entry point.
        '''
        # Delete file if it exists
        try:
            os.remove(tftp.DOWNLOAD_DIR + 'garden-verses.txt')
        except FileNotFoundError:
            pass
        
        client = tftp.Client()
        
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # Create a thread that sends `garden-verses.txt`
        t = Thread(target=client.sendFile, args=['127.0.0.1', 'garden-verses.txt'])
        t.start()

        # First it will send WRQ, receive that and send back ACK 0
        payload, (client_address, client_port) = srv.recvfrom(1024)
        blockNum = 0
        srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))

        self.assertEqual(tftp.createConnectionPacket('w', 'garden-verses.txt'), payload)
        
        # Then it will send many 512 byte blocks; receive them and acknowledge them 
        fileBuffer = bytes(0)
        blockNum = 1
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 1)
        srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))

        while True:
            blockNum += 1
            payload, (client_address, client_port) = srv.recvfrom(1024)
            self.assertEqual(int.from_bytes(payload[2:4]), blockNum)
            fileBuffer += payload[4:]
            srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))
            if len(payload) < 516:
                break

        blockNum += 1
        # self.assertEqual(int.from_bytes(payload[2:4]), blockNum)
        self.assertTrue(len(payload[4:]) < 512)
        srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))
        
        t.join(0.5)
        srv.close()
        with open(tftp.DOWNLOAD_DIR + 'garden-verses.txt', 'w+') as file:
            file.write(str(fileBuffer, encoding='utf8'))
        
        self.assertTrue(os.path.isfile(tftp.DOWNLOAD_DIR + 'garden-verses.txt'))
        
        # Delete file now that test is done
        try:
            os.remove(tftp.DOWNLOAD_DIR + 'garden-verses.txt')
        except FileNotFoundError:
            pass 

    def test_sent_handle_diskfull_last_packet(self):
        '''
        The client should return false if a disk full error is received during transfer of a file
        instead of the acknowledgment of the last packet.
        '''
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # Create new thread that sends blocks
        big_block = bytes('honeybee', 'utf8') * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        
        with open(tftp.UPLOAD_DIR + 'fulltest.txt', 'w+') as tempfile:
            tempfile.write(str(buffer, encoding='utf8'))
        
        sendingResult = Queue()
        t = Thread(target=lambda sendingResult: sendingResult.put(client.sendFile('127.0.0.1', 'fulltest.txt')), args=[sendingResult])
        t.start()
        
        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(tftp.createConnectionPacket('w', 'fulltest.txt'), payload)

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 12225))
        
        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.createAckPacket(0), (client_address, client_port))
                        
        # Receive and acknowledge blocks 1, 2, 3
        for blockNum in range(1, 3+1):
            payload, (client_address, client_port) = srv.recvfrom(1024)
            
            # Verify block number of data block
            self.assertEqual(int.from_bytes(payload[2:4]), blockNum)
            
            # Verify contents
            self.assertEqual(payload[4:], big_block)
            
            # Acknowledge data block
            srv.sendto(tftp.createAckPacket(blockNum), (client_address, client_port))
        
        # Receive final block 4 and send a DISK_FULL error.
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 4)
        self.assertEqual(payload[4:], lil_block)
        srv.sendto(tftp.createErrorPacket(tftp.ErrorCodes.DISK_FULL), (client_address, client_port))

        t.join(0.5)
        
        self.assertEqual(sendingResult.qsize(), 1)
        self.assertFalse(sendingResult.get())
        
        srv.close()

if __name__ == "__main__":
    unittest.main()