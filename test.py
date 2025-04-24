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
import unittest
import socket
from threading import Thread

# Modules from this project
import main


class RequestPacketCreationTests(unittest.TestCase):
    def test_bad_request_type(self):
        # There is no "x" mode, it's either 'r' or 'w'
        badCall = lambda : main.createConnectionPacket('x', 'x.png')
        self.assertRaises(ValueError, badCall)
    
    def test_bad_request_mode(self):
        # There is no unicode mode - this should raise an exception
        badCall = lambda : main.createConnectionPacket('r', 'x.png', 'unicode')
        self.assertRaises(ValueError, badCall)
    
    def test_good_write_requests(self):
        req = main.createConnectionPacket('w', 'document.txt')
        exp = b'\x00\x02document.txt\x00octet\x00'
        self.assertEqual(req, exp)
        
        req = main.createConnectionPacket('w', 'image.png', mode='netascii')
        exp = b'\x00\x02image.png\x00netascii\x00'
        self.assertEqual(req, exp)
    
    def test_good_read_requests(self):
        req = main.createConnectionPacket('r', 'hello.txt')
        exp = b'\x00\x01hello.txt\x00octet\x00'
        self.assertEqual(req, exp)
        
        req = main.createConnectionPacket('r', 'world.png', mode='netascii')
        exp = b'\x00\x01world.png\x00netascii\x00'
        self.assertEqual(req, exp)

class DataPacketCreationTests(unittest.TestCase):
    def test_bad_block_number(self):
        for badNum in [-10, -1, 1000, 2048]:
            badCall = lambda : main.createDataPacket(badNum, bytes(badNum))
            self.assertRaises(ValueError, badCall)

    def test_no_data_ok(self):
        pkt = main.createDataPacket(5, bytes(0))
        exp = b'\x00\x03\x00\x05'
        self.assertEqual(pkt, exp)
    
    def test_ok_sizes(self):
        for num in [512, 5, 17, 1, 511, 256]:
            pkt = main.createDataPacket(5, bytes(num))
            exp = b'\x00\x03\x00\x05' + bytes(num)
            self.assertEqual(pkt, exp)
    
    def test_encoded_bytes(self):
        # Chinese characters, full width ！ (not !), then some ascii digits
        data = bytes('大林和小林是一本很有意思的小说！ 12345678', 'utf8')
        pkt = main.createDataPacket(2, data)
        exp = b'\x00\x03\x00\x02' + data
        self.assertEqual(exp, pkt)

class AckPacketCreationTests(unittest.TestCase):
    def test_bad_block_number(self):
        for badNum in [-10, -1, 1000, 2048]:
            badCall = lambda : main.createAckPacket(badNum)
            self.assertRaises(ValueError, badCall)
    
    def test_ok_block_number(self):
        for num in [5, 17, 1, 511, 256]:
            pkt = main.createAckPacket(num)
            exp = b'\x00\x04' + int(num).to_bytes(2)
            self.assertEqual(pkt, exp)

class ErrorPacketCreationTests(unittest.TestCase):
    def test_bad_code(self):
        badCall = lambda : main.createErrorPacket(int(255).to_bytes(2), 'hella, warld!')
        self.assertRaises(ValueError, badCall)

    def test_valid_codes(self):
        for num in range(1, 7+1):
            err = main.createErrorPacket(num.to_bytes(2))
            exp = b'\x00\x05' + num.to_bytes(2) + bytes(1)
            
class ClientBehaviourTests(unittest.TestCase):
    def test_create_bind(self):
        client = main.Client()
        
        self.assertIsNotNone(client.sourcePort)
        self.assertEqual(client.sourcePort, client.sock.getsockname()[1])
    
    def test_write_request(self):
        client = main.Client()
        
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 11111))
        
        # Make a read request, put it in a thread so it can block for our response
        t = Thread(target = client.requestWrite, args=['0.0.0.0', 'doc.txt'])
        t.start()
        payload, (client_address, client_port) = srv.recvfrom(1024)
        
        # Verify what was received by the server
        self.assertEqual(main.createConnectionPacket('w', 'doc.txt'), payload)

        # Send the ACK from a different socket
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('0.0.0.0', 12222))

        # Send acknowledgment
        srv.sendto(main.createAckPacket(0), (client_address, client_port))

        # Wait for client thread to finish, so we can check state of client
        t.join()
        
        self.assertEqual(client.destinationPort, 12222)
        
        srv.close()
        

if __name__ == "__main__":
    unittest.main()