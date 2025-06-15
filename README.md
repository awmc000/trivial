# trivial
Trivial File Transfer Protocol (TFTP) client and server implementation from RFC 1350.

## Use case

With `trivial`, you can quickly send a file between two hosts on the same 
LAN with no setup or configuration. It can take the place of a USB stick or
a cumbersome interaction with a cloud file storage service; just listen on
one host and send or receive the file from the other host. Your file is 
transported quickly and reliably using the Trivial File Transfer Protocol.

## Features and design choices

- Stop and wait algorithm for flow control using acknowledgements.
- Clients and servers will not overwrite existing files.
- A client or server sends files *from* the `share` directory.
- A client or server retrieves files *to* the `downloads` directory.
- They will read and write to these directories only.
- The filepath arguments received will be interpreted as relative paths from the appropriate directory.
    - This means that access violations will only occur if there is a file in the share dir the program
    is not allowed to read.
    - `share/unreadable.txt` is a text file with 000 permissions made for this purpose.
- Each host running the program has both the client and server. It is a single application used via CLI.
- Considering adding a packet type which is used to check if the other endpoint is listening.
    - like a health check/ping/throwaway message (nothing happens then life is good, else ICMP port unreachable received)

## Usage and example output

### Run a server

```
$ python -m trivial listen
hh:mm:ss ... Listening ...
hh:mm:ss Accepted write request 'doc.txt'
hh:mm:ss Receiving blocks for 'doc.txt': [███████░░░]
hh:mm:ss Finished serving write request 'doc.txt', connection closed.
hh:mm:ss ... Listening ...
hh:mm:ss Declined write request 'doc.txt': file already exists
```

### Request a file

```
$ python -m trivial read doc.txt 192.168.0.15
hh:mm:ss ... Making read request for 'doc.txt' ...
hh:mm:ss read request for 'doc.txt' accepted
hh:mm:ss ... Receiving blocks for 'doc.txt': [█████░░░░░] ...
hh:mm:ss Finished receiving 'doc.txt' data, connection closed.
hh:mm:ss New file is located at {clickable folder link}
```

### Send a file

```
$ python -m trivial write doc.txt 192.168.0.15
hh:mm:ss ... Making write request for 'doc.txt' ...
hh:mm:ss write request for 'doc.txt' accepted
hh:mm:ss ... sending blocks for 'doc.txt': [██░░░░░░░░] ...
hh:mm:ss Finished sending 'doc.txt' data, connection closed.
hh:mm:ss New file is located at {clickable folder link} on host {ip address}.
```

## License

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