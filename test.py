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

test.py: unit tests for all parts of the program
"""

# Modules from std library
from queue import Queue
from threading import Thread
import select
import time
import unittest
import socket
import os

# Modules from this project
import tftp


class RequestPacketCreationTests(unittest.TestCase):
    """
    Tests for the utility functions for creating valid TFTP WRQ/RRQ packets.
    """

    def test_bad_request_type(self):
        # There is no "x" mode, it's either 'r' or 'w'
        def create_bad_request():
            tftp.create_connection_packet("x", "x.png")

        self.assertRaises(ValueError, create_bad_request)

    def test_bad_request_mode(self):
        # There is no unicode mode - this should raise an exception
        def create_bad_request():
            tftp.create_connection_packet("r", "x.png", "unicode")

        self.assertRaises(ValueError, create_bad_request)

    def test_good_write_requests(self):
        req = tftp.create_connection_packet("w", "document.txt")
        exp = b"\x00\x02document.txt\x00octet\x00"
        self.assertEqual(req, exp)

        req = tftp.create_connection_packet("w", "image.png", mode="netascii")
        exp = b"\x00\x02image.png\x00netascii\x00"
        self.assertEqual(req, exp)

    def test_good_read_requests(self):
        req = tftp.create_connection_packet("r", "hello.txt")
        exp = b"\x00\x01hello.txt\x00octet\x00"
        self.assertEqual(req, exp)

        req = tftp.create_connection_packet("r", "world.png", mode="netascii")
        exp = b"\x00\x01world.png\x00netascii\x00"
        self.assertEqual(req, exp)


class DataPacketCreationTests(unittest.TestCase):
    """
    Tests for the utility functions for creating valid TFTP data packets.
    """

    def test_bad_block_number(self):
        """
        Tests that trying to create a data packet with a bad block num
        raises a ValueError.
        """

        for bad_num in [-10, -1, 1000, 2048]:

            def bad_call():
                tftp.create_data_packet(bad_num, bytes(bad_num))

            self.assertRaises(ValueError, bad_call)

    def test_no_data_ok(self):
        """
        Tests that it is OK to create a 0-byte data packet. This is intended behaviour.
        When a host sends a file that is exactly 512 bytes, the other host takes the
        length as a signal to expect more blocks, so we need to send a block of less than
        512 bytes to cut off the transfer, hence the empty block.
        """
        pkt = tftp.create_data_packet(5, bytes(0))
        exp = b"\x00\x03\x00\x05"
        self.assertEqual(pkt, exp)

    def test_ok_sizes(self):
        for num in [512, 5, 17, 1, 511, 256]:
            pkt = tftp.create_data_packet(5, bytes(num))
            exp = b"\x00\x03\x00\x05" + bytes(num)
            self.assertEqual(pkt, exp)

    def test_encoded_bytes(self):
        # Chinese characters, full width ！ (not !), then some ascii digits
        data = bytes("大林和小林是一本很有意思的小说！ 12345678", "utf8")
        pkt = tftp.create_data_packet(2, data)
        exp = b"\x00\x03\x00\x02" + data
        self.assertEqual(exp, pkt)


class AckPacketCreationTests(unittest.TestCase):
    """
    Tests for the utility functions for creating valid TFTP acknowledgment (ACK) packets.
    """

    def test_bad_block_number(self):
        for bad_num in [-10, -1, 1000, 2048]:

            def create_bad_ack():
                tftp.create_ack_packet(bad_num)

            self.assertRaises(ValueError, create_bad_ack)

    def test_ok_block_number(self):
        for num in [5, 17, 1, 511, 256]:
            pkt = tftp.create_ack_packet(num)
            exp = b"\x00\x04" + int(num).to_bytes(2)
            self.assertEqual(pkt, exp)


class ErrorPacketCreationTests(unittest.TestCase):
    """
    Tests for the utility functions for creating valid TFTP error packets.
    """

    def test_bad_code(self):
        def make_bad_error():
            tftp.create_error_packet(int(255).to_bytes(2), "hella, warld!")

        self.assertRaises(ValueError, make_bad_error)

    def test_valid_codes(self):
        for num in range(1, 7 + 1):
            err = tftp.create_error_packet(num.to_bytes(2))
            exp = b"\x00\x05" + num.to_bytes(2) + bytes(1)
            self.assertEqual(err, exp)


class ClientBehaviourTests(unittest.TestCase):
    """
    Tests of client behaviour, aiming for compliance with RFC 1350 and
    project specific design choices.
    """

    def test_create_bind(self):
        client = tftp.Client()
        self.assertIsNotNone(client.source_port)
        self.assertEqual(client.source_port, client.sock.getsockname()[1])

    def test_write_request_timeout(self):
        """
        Tests triggering a client to timeout by not sending ACK 0 to WRQ
        """
        client = tftp.Client()
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))
        t = Thread(
            target=self.assertRaises,
            args=[IOError, lambda: client.request_write("127.0.0.1", "doc.txt")],
        )
        t.start()
        t.join(0.75)
        srv.close()

    def test_write_request(self):
        """
        Tests client sending WRQ and server replying with ACK.
        """
        client = tftp.Client()
        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))
        # Make a write request, put it in a thread so it can block for our response
        t = Thread(target=client.request_write, args=["0.0.0.0", "doc.txt"])
        t.start()
        payload, (client_address, client_port) = srv.recvfrom(1024)
        # Verify what was received by the server
        self.assertEqual(tftp.create_connection_packet("w", "doc.txt"), payload)

        # Send the ACK from a different socket
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12222))
        srv.sendto(tftp.create_ack_packet(0), (client_address, client_port))

        # Wait for client thread to finish, so we can check state of client
        t.join(0.5)
        self.assertEqual(client.destination_port, 12222)
        srv.close()

    def test_read_request(self):
        """
        Tests client sending RRQ and server replying with first packet.
        """
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # Make a read request, put it in a thread so it can block for our response
        t = Thread(target=client.get_file, args=["0.0.0.0", "doc.txt"])
        t.start()
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server
        self.assertEqual(tftp.create_connection_packet("r", "doc.txt"), payload)

        # Send one segment from a different socket
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12223))
        srv.sendto(
            tftp.create_data_packet(1, bytes("Hello, World!", "utf8")),
            (client_address, client_port),
        )
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server
        self.assertEqual(tftp.create_ack_packet(1), payload)
        t.join(0.5)
        srv.close()

    def test_accepted_requests_return_true(self):
        """
        Tests that the client methods return True when WRQs or RRQs are
        accepted.
        """

        # Create a thread function that acts like a server
        # that approves N requests and then quits.
        def nice_server(request_quota):
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("0.0.0.0", 11111))

            approved = 0
            while approved < request_quota:
                payload, (client_address, client_port) = srv.recvfrom(1024)

                if payload[:2] == b"\x00\x01":
                    # It's a read request, send a fake block 1.
                    srv.sendto(
                        tftp.create_data_packet(1, bytes("Hello, World!", "utf8")),
                        (client_address, client_port),
                    )
                    approved += 1
                elif payload[:2] == b"\x00\x02":
                    # It's a write request, send a fake ack 0.
                    srv.sendto(
                        tftp.create_ack_packet(0),
                        (client_address, client_port),
                    )
                    approved += 1
            srv.close()

        t = Thread(target=nice_server, args=[2])
        t.start()

        client = tftp.Client()

        self.assertTrue(client.request_read("127.0.0.1", "nexist.txt"))
        self.assertTrue(client.request_write("127.0.0.1", "nexist.txt"))

        t.join()

    def test_receive(self):
        """
        Tests ability to receive packets and send acknowledgement.
        """
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # We will send 5 blocks, 4 of size 512, and then one of 511 bytes
        full_message = 64 * bytes("honeybee", "utf8")
        short_message = full_message[:511]

        # request_write would also usually bind block_num
        # request_write would also receive the first block
        client.buffer = full_message
        client.block_num = 1

        # Create thread where client receives blocks
        t = Thread(target=client.receive)
        t.start()

        for i in range(1, 4):
            # Send a block, receive ACK, check that it is correct
            srv.sendto(full_message, ("127.0.0.1", client.source_port))
            payload = srv.recvfrom(1024)[0]
            acknowledged = int.from_bytes(payload[2:])
            self.assertEqual(acknowledged, i + 1)

        srv.sendto(short_message, ("127.0.0.1", client.source_port))
        payload = srv.recvfrom(1024)[0]
        acknowledged = int.from_bytes(payload[2:])
        self.assertEqual(acknowledged, 5)
        t.join(0.5)
        self.assertEqual(client.block_num, 5)
        srv.close()

    def test_send(self):
        """
        Client can send a multi-block buffer to the server properly
        """
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))
        # From client, make a write request, then join thread
        t = Thread(target=client.request_write, args=["127.0.0.1", "honeybee.txt"])
        t.start()
        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(tftp.create_connection_packet("w", "honeybee.txt"), payload)

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12224))

        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.create_ack_packet(0), (client_address, client_port))
        t.join(0.5)

        # The client should have set destinationAddress and destinationPort now
        self.assertEqual(client.destination_address, "127.0.0.1")
        self.assertEqual(client.destination_port, 12224)

        # Create new thread that sends blocks
        big_block = bytes("honeybee", "utf8") * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        t = Thread(target=client.send, args=[buffer])
        t.start()

        # Receive and acknowledge blocks 1, 2, 3
        for block_num in range(1, 3 + 1):
            payload, (client_address, client_port) = srv.recvfrom(1024)

            # Verify block number of data block
            self.assertEqual(int.from_bytes(payload[2:4]), block_num)

            # Verify contents
            self.assertEqual(payload[4:], big_block)

            # Acknowledge data block
            srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))

        # Receive and acknowledge final block 4
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 4)
        self.assertEqual(payload[4:], lil_block)
        srv.sendto(tftp.create_ack_packet(4), (client_address, client_port))

        t.join(0.5)
        srv.close()

    def test_send_file(self):
        """
        Send a *large* multi block file from the client using the proper entry point.
        """
        # Delete file if it exists
        try:
            os.remove(tftp.DOWNLOAD_DIR + "garden-verses.txt")
        except FileNotFoundError:
            pass

        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # Create a thread that sends `garden-verses.txt`
        t = Thread(target=client.send_file, args=["127.0.0.1", "garden-verses.txt"])
        t.start()

        # First it will send WRQ, receive that and send back ACK 0
        payload, (client_address, client_port) = srv.recvfrom(1024)
        block_num = 0
        srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))

        self.assertEqual(
            tftp.create_connection_packet("w", "garden-verses.txt"), payload
        )

        # Then it will send many 512 byte blocks; receive them and acknowledge them
        file_buffer = bytes(0)
        block_num = 1
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 1)
        srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))

        while True:
            block_num += 1
            payload, (client_address, client_port) = srv.recvfrom(1024)
            self.assertEqual(int.from_bytes(payload[2:4]), block_num)
            file_buffer += payload[4:]
            srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))
            if len(payload) < 516:
                break

        block_num += 1

        self.assertTrue(len(payload[4:]) < 512)
        srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))
        t.join(0.5)
        srv.close()

        with open(
            tftp.DOWNLOAD_DIR + "garden-verses.txt", "w+", encoding="utf8"
        ) as file:
            file.write(str(file_buffer, encoding="utf8"))
        self.assertTrue(os.path.isfile(tftp.DOWNLOAD_DIR + "garden-verses.txt"))

        # Delete file now that test is done
        try:
            os.remove(tftp.DOWNLOAD_DIR + "garden-verses.txt")
        except FileNotFoundError:
            pass

    def test_sent_handle_diskfull_last_packet(self):
        """
        The client should return false if a disk full error is received during transfer of a file
        instead of the acknowledgment of the last packet.
        """
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # Create new thread that sends blocks
        big_block = bytes("honeybee", "utf8") * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        with open(tftp.UPLOAD_DIR + "fulltest.txt", "w+") as tempfile:
            tempfile.write(str(buffer, encoding="utf8"))
        send_attempt_result = Queue()

        def client_send():
            send_attempt_result.put(client.send_file("127.0.0.1", "fulltest.txt"))

        t = Thread(target=client_send)
        t.start()
        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(tftp.create_connection_packet("w", "fulltest.txt"), payload)

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12225))

        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.create_ack_packet(0), (client_address, client_port))

        # Receive and acknowledge blocks 1, 2, 3
        for block_num in range(1, 3 + 1):
            payload, (client_address, client_port) = srv.recvfrom(1024)

            # Verify block number of data block
            self.assertEqual(int.from_bytes(payload[2:4]), block_num)

            # Verify contents
            self.assertEqual(payload[4:], big_block)

            # Acknowledge data block
            srv.sendto(tftp.create_ack_packet(block_num), (client_address, client_port))

        # Receive final block 4 and send a DISK_FULL error.
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 4)
        self.assertEqual(payload[4:], lil_block)
        srv.sendto(
            tftp.create_error_packet(tftp.ErrorCodes.DISK_FULL),
            (client_address, client_port),
        )

        t.join(0.5)
        self.assertEqual(send_attempt_result.qsize(), 1)
        self.assertFalse(send_attempt_result.get())
        srv.close()
        os.remove(tftp.UPLOAD_DIR + "fulltest.txt")

    def test_send_no_ack(self):
        """
        The client should return false if, when attempting to send a file,
        the WRQ is accepted but the first data packet is never acknowledged.
        """
        client = tftp.Client()

        # Set up socket to stand in for server
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # Create new thread that sends blocks
        big_block = bytes("honeybee", "utf8") * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        with open(tftp.UPLOAD_DIR + "fulltest.txt", "w+") as tempfile:
            tempfile.write(str(buffer, encoding="utf8"))

        send_attempt_result = Queue()

        def client_send():
            send_attempt_result.put(client.send_file("127.0.0.1", "fulltest.txt"))

        t = Thread(target=client_send)
        t.start()
        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(tftp.create_connection_packet("w", "fulltest.txt"), payload)

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12225))

        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.create_ack_packet(0), (client_address, client_port))

        # Calculate how long it will take to timeout
        wait = tftp.OPERATION_ATTEMPTS * tftp.OPERATION_TIMEOUT

        t.join(wait)
        self.assertEqual(send_attempt_result.qsize(), 1)
        self.assertFalse(send_attempt_result.get())
        srv.close()
        os.remove(tftp.UPLOAD_DIR + "fulltest.txt")

    def test_client_ports_random(self):
        """
        Client ports are selected randomly, by making N clients
        and testing that they have N different ports.
        """

        n = 50
        clients = []
        for _ in range(n):
            clients.append(tftp.Client())
        seen = set()

        for c in clients:
            self.assertNotIn(c.source_port, seen)
            self.assertNotIn(c.sock.getsockname()[1], seen)
            seen.add(c.source_port)

        self.assertEqual(len(seen), n)

    def test_ack_wrong_source_port(self):
        """
        Sets up a file transfer from client to server (WRQ). Tests that the
        client will send error packets with type 5 (Unknown transfer ID) when
        it receives a packet from the wrong port. This should be checked
        AHEAD of whether it is the correct type etc.

        Suppose a client is making a write, and is waiting for ACK 26 from port 2222.
        If it receives an ACK 26 from any other port, it will ignore as many as
        arrive. If a bazillion packets (we will use slightly less in this test) arrive that
        are identical except the source TID (port), and a single one arrives that
        has the correct block number and port, the transfer should continue uninterrupted.

        This behaviour is described in the RFC as follows:

        > "If a source TID does not match, the packet should be
        > discarded as erroneously sent from somewhere else. An error packet
        > should be sent to the source of the incorrect packet, while not
        > disturbing the transfer."
        """

        client = tftp.Client()

        # Set up socket to stand in for server listening at KNOWN_PORT
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 11111))

        # From client, make a write request, then join thread
        t = Thread(target=client.request_write, args=["127.0.0.1", "garden-verses.txt"])
        t.start()

        # Receive write request
        payload, (client_address, client_port) = srv.recvfrom(1024)

        # Verify what was received by the server at KNOWN_PORT
        self.assertEqual(
            tftp.create_connection_packet("w", "garden-verses.txt"), payload
        )

        # Put server on a new port in keeping with defined server behaviour
        srv.close()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", 12224))

        # Set up a socket playing the role of an interrupting server
        # It will attempt to distract the client and test its ability to resist >:)
        distracting_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        distracting_srv.setblocking(False)
        distracting_srv.bind(("0.0.0.0", 11223))

        # Send ACK 0 from new TID (port)
        srv.sendto(tftp.create_ack_packet(0), (client_address, client_port))
        t.join(0.5)

        # The client should have set destinationAddress and destinationPort now
        self.assertEqual(client.destination_address, "127.0.0.1")
        self.assertEqual(client.destination_port, 12224)

        # Create new thread that sends blocks
        big_block = bytes("honeybee", "utf8") * 64
        lil_block = big_block[:504]
        buffer = big_block + big_block + big_block + lil_block
        t = Thread(target=client.send, args=[buffer])
        t.start()

        # Receive and acknowledge blocks 1, 2, 3
        for block_num in range(1, 3 + 1):
            payload, (client_address, client_port) = srv.recvfrom(1024)

            # Verify block number of data block
            self.assertEqual(int.from_bytes(payload[2:4]), block_num)

            # Verify contents
            self.assertEqual(payload[4:], big_block)

            # Send a bad acknowledgement which the client must ignore
            distracting_srv.sendto(
                tftp.create_ack_packet(block_num), (client_address, client_port)
            )
            distracting_srv_ready = select.select([distracting_srv], [], [], 1.0)
            if distracting_srv_ready[0]:
                error_payload = distracting_srv.recvfrom(1024)[0]

                # Check that the client sent back an ERROR packet with type 5, unknown TID
                self.assertEqual(
                    tftp.create_error_packet(tftp.ErrorCodes.UNKNOWN_TID), error_payload
                )

                # Acknowledge data block
                srv.sendto(
                    tftp.create_ack_packet(block_num), (client_address, client_port)
                )
            else:
                srv.close()
                self.fail()

        # Receive and acknowledge final block 4
        payload, (client_address, client_port) = srv.recvfrom(1024)
        self.assertEqual(int.from_bytes(payload[2:4]), 4)
        self.assertEqual(payload[4:], lil_block)
        srv.sendto(tftp.create_ack_packet(4), (client_address, client_port))

        t.join(0.5)
        srv.close()
        distracting_srv.close()


def wait_for_udp_port(
    host: str, port: int, timeout: float = 2.0, interval: float = 0.05
):
    """
    Waits for a UDP server to bind to a given port.
    Returns True if successful, raises TimeoutError if not.
    [This function was generated by an LLM.]
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            # Send a harmless packet to the server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(interval)
            s.sendto(b"\xc0\xde", (host, port))  # dummy byte
            # If no exception, assume port is open
            return True
        except (ConnectionRefusedError, OSError):
            # Server not ready yet
            time.sleep(interval)
        finally:
            s.close()
    raise TimeoutError(
        f"Server did not bind to {host}:{port} within {timeout} seconds."
    )


class ServerBehaviourTests(unittest.TestCase):
    """
    Tests of server behaviour, aiming for compliance with RFC 1350 and
    project specific design choices.
    """

    def run_server(self, quota: int = 1):
        """
        Helper function that runs a server; meant to be run in a separate thread for tests.
        """
        server = tftp.Server()
        server.quota = quota
        server.listen()

    def test_create_bind(self):
        """
        Tests that a server binds its listener socket as part of setup (the constructor).
        """
        server = tftp.Server()
        self.assertIsNotNone(server.listener_sock)
        self.assertEqual(tftp.KNOWN_PORT, server.listener_sock.getsockname()[1])

    def test_accept_good_rrq(self):
        """
        Server will accept well-formed read requests (RRQs).
        FIXME: This test is not fully consistent, it fails sometimes (!!!!)
        """
        t = Thread(target=self.run_server)
        t.start()

        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        # Create faked out client on a random port
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Create a file
        filepath = tftp.UPLOAD_DIR + "quote.md"
        with open(filepath, "w+") as file:
            file.write(
                "# Quote\n"
                '"Computer Science is no more about computers than astronomy is about telescopes."'
                " - *Dijkstra*"
            )

        # Send a well formed read request for the file
        rrq = tftp.create_connection_packet("r", "quote.md")

        client.settimeout(2.0)
        client.sendto(rrq, ("localhost", tftp.KNOWN_PORT))

        # Make sure we receive block 1 which serves as ACK
        # FIXME: The test Times out here in some cases, especially if run a few times in succession
        payload = client.recv(1024)

        self.assertEqual(payload[:2], b"\x00\x03")
        # print(f'packet type check: {payload[:2] == b"\x00\x03"}')

        client.close()
        os.remove(filepath)
        t.join()

    def test_decline_rrq_file_not_exist(self):
        """
        Server will reply with an error to a RRQ
        for a file that does not exist.
        """
        t = Thread(target=self.run_server)
        t.start()

        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Send a well formed read request for the file
        rrq = tftp.create_connection_packet("r", "dontexist.txt")

        client.settimeout(2.0)
        client.sendto(rrq, ("localhost", tftp.KNOWN_PORT))

        payload = client.recv(1024)

        # Check that message type is 5 ERROR
        self.assertEqual(payload[:2], b"\x00\x05")

        # Check that error type is 1 FILE NOT FOUND
        self.assertEqual(payload[2:4], b"\x00\x01")

        t.join()
        client.close()

    def test_decline_rrq_cant_read_file(self):
        """
        Tests that the server will reply with an error to a RRQ
        for a file that the client is not allowed to read.
        """
        t = Thread(target=self.run_server)
        t.start()
        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Send a well formed read request for a file a user program can't read.
        rrq = tftp.create_connection_packet("r", "unreadable.txt")

        client.settimeout(2.0)
        client.sendto(rrq, ("localhost", tftp.KNOWN_PORT))

        payload = client.recv(1024)

        # Check that message type is 5 ERROR
        self.assertEqual(payload[:2], b"\x00\x05")

        # Check that error type is 2 ACCESS VIOLATION
        self.assertEqual(payload[2:4], b"\x00\x02")

        t.join()
        client.close()

    def test_accept_good_wrq(self):
        """
        Server will accept well-formed write requests (WRQs).
        """
        t = Thread(target=self.run_server)
        t.start()
        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Send wrq and expect ACK 0
        wrq = tftp.create_connection_packet("w", "garden-verses.txt")

        client.settimeout(2.0)
        client.sendto(wrq, ("localhost", tftp.KNOWN_PORT))

        payload = client.recv(1024)

        self.assertEqual(payload, b"\x00\x04\x00\x00")

        # clean up
        t.join()
        client.close()

    def test_complete_valid_wrq(self):
        """
        Server will accept AND fully complete a valid WRQ file transfer.
        """
        t = Thread(target=self.run_server)
        t.start()
        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Send wrq and expect ACK 0
        wrq = tftp.create_connection_packet("w", "garden-verses.txt")

        client.settimeout(2.0)
        client.sendto(wrq, ("localhost", tftp.KNOWN_PORT))

        payload, (initial_server_address, initial_server_port) = client.recvfrom(1024)

        self.assertEqual(payload, b"\x00\x04\x00\x00")

        # Send blocks and expect ACK 1 to ACK N
        buf = bytes(0)
        block_num = 1
        with open(tftp.UPLOAD_DIR + "garden-verses.txt", "w+", encoding="utf8") as file:
            buf += bytes(file.read(), encoding="utf8")

        while len(buf) > 0:
            block = tftp.create_data_packet(block_num, buf[:512])
            buf = buf[512:]
            client.sendto(block, ("localhost", tftp.KNOWN_PORT))
            payload, (server_address, server_port) = client.recvfrom(1024)

            self.assertEqual(server_address, initial_server_address)
            self.assertNotEqual(server_port, tftp.KNOWN_PORT)
            self.assertNotEqual(server_port, initial_server_port)

            self.assertEqual(payload[:2], b"\x00\x04")
            self.assertEqual(payload[2:4], block_num.to_bytes(2))

            block_num += 1

        # clean up
        t.join()
        client.close()

    def test_decline_wrq_file_exists(self):
        """
        Server will reply with an error to a WRQ for an existing file.
        """
        # TODO : make WRQ for "doc.txt", should be rejected b/c it already exists.
        t = Thread(target=self.run_server)
        t.start()
        wait_for_udp_port("localhost", tftp.KNOWN_PORT)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("0.0.0.0", 0))

        # Send wrq and expect ACK 0
        wrq = tftp.create_connection_packet("w", tftp.UPLOAD_DIR + "garden-verses.txt")

        client.settimeout(2.0)
        client.sendto(wrq, ("localhost", tftp.KNOWN_PORT))

        payload = client.recv(1024)

        # Check that message type is 5 ERROR
        self.assertEqual(payload[:2], b"\x00\x05")

        # Check that error type is 6 FILE ALREADY EXISTS
        self.assertEqual(payload[2:4], b"\x00\x06")

        client.close()
        t.join()


if __name__ == "__main__":
    unittest.main()
