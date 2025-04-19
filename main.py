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
'''

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
    
    if type == 'r':
        opcode = Opcodes.READ_REQUEST
    elif type == 'w':
        opcode = Opcodes.WRITE_REQUEST
    
    # Start with opcode
    req = opcode
    
    # Filename 
    req += bytes(filename, 'ascii')
    
    # Empty byte (arg is 1 because we want it 1 byte long)
    req += bytes(1)
    
    # Mode string
    req += bytes(mode, 'ascii')
    
    # Empty byte
    req += bytes(1)
    
    return req

def createDataPacket(blockNumber: int, data: bytes):
    '''
    Creates a formatted data packet ready to send through UDP.
    '''
    if len(data) > 512:
        raise ValueError('Data packets\' contents should be strictly [0, 512] bytes in length.')
    
    pkt = Opcodes.DATA
    pkt += blockNumber.to_bytes(2)
    pkt += data
    
    return pkt

def createAckPacket(blockNumber: int):
    '''
    Creates a formatted acknowledgement packet ready to send through UDP.
    '''
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
    err = Opcodes.ERROR
    err += code
    err += bytes(errorMessage, 'ascii')
    err += bytes(1) # one byte, value is zero
    
    return err
