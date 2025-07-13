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

trivial.py: terminal user interface
"""

import sys
from pathlib import Path

from tftp import Client, Server

TUI_TEXT = {
    "usage": "Usage:\nrun server\t-> trivial listen"
    "\nget file\t-> trivial read FILE_NAME IP_ADDRESS"
    "\nsend file\t-> trivial write FILE_NAME IP_ADDRESS",
    "bad_ip": "Invalid IP address. Should be an IPv4 address in dotted decimal form.",
    "bad_file_path": "Invalid file path. Is that the name of a file in"
    " the source's share directory?",
    "send_success": "sent successfully!",
    "send_failure": "failed to send file",
    "read_success": "read successfully!",
    "read_failure": "failed to read file",
}


def is_ip_address(addr: str):
    segments = addr.split(".")

    if len(segments) != 4:
        return False

    for seg in segments:

        # Fail an empty segment
        if not seg:
            return False

        # Fail if non-number
        if not seg.isnumeric():
            return False

        # Fail if there is zero-padding
        if seg[0] == "0" and len(seg) > 1:
            return False

        # Fail if number is out of bounds
        value = int(seg)
        if value < 0 or value > 255:
            return False

    return True

def files_shared():
    share_dir = Path('./share')
    files = list(share_dir.iterdir())
    acceptable = [ f.name for f in files ]
    return acceptable

def is_valid_file_path(path: str):
    """
    Returns `True` if `path` is a valid filename.
    """
    return path in files_shared()

def handle_bad_parameters():
    file_name = sys.argv[2]
    ip_address = sys.argv[3]

    if not is_valid_file_path(file_name):
        print(TUI_TEXT["bad_file_path"])
        return -1

    if not is_ip_address(ip_address):
        print(TUI_TEXT["bad_ip"])
        return -1

    return (file_name, ip_address)


def handle_read():
    client = Client()

    try:
        file_name, ip_address = handle_bad_parameters()
    except TypeError:
        return -1

    success = client.get_file(ip_address, file_name)

    if success:
        print(TUI_TEXT["read_success"])
        return 0

    print(TUI_TEXT["read_failure"])
    return 0


def handle_write():
    client = Client()

    try:
        file_name, ip_address = handle_bad_parameters()
    except TypeError:
        return -1

    success = client.send_file(ip_address, file_name)

    if success:
        print(TUI_TEXT["send_success"])
        return 0
    print(TUI_TEXT["send_failure"])
    return 0


def main() -> int:

    # Should be at least two args: 'trivial' and 'listen', or 3 args for read/write
    if len(sys.argv) < 2:
        print(TUI_TEXT["usage"])
        return -1

    command = sys.argv[1]

    if command == "listen":
        server = Server()
        while True:
            server.listen()

    if len(sys.argv) == 2 and sys.argv[1] == "write":
        print(f'files shared: {', '.join(files_shared())}')

    # Other commands take 3 arguments, read|write FILE_NAME IP_ADDRESS
    if len(sys.argv) < 4:
        print(TUI_TEXT["usage"])
        return -1

    if command == "read":
        return handle_read()

    if command == "write":
        return handle_write()

    return 0


if __name__ == "__main__":
    sys.exit(main())
