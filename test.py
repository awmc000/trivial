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
import unittest
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
            badCall = lambda : main.createDataPacket(-1, bytes(badNum))
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

if __name__ == "__main__":
    unittest.main()