"""
Flex Packet Processing Script

This script provides a set of classes and functions to handle Flex packets, 
which are used in communication systems for data transmission. The script includes 
definitions for various packet types, checksum algorithms, and operations related to 
Flex packets such as creation, parsing, and checksum verification.

Classes:
- FlexPacketType (Enum): Enumerates different types of Flex packets.
- ChecksumType (Enum): Enumerates different types of checksum algorithms.
- TimeBase: Represents a time base used in Flex packets.
- Entity: Represents an entity in a Flex packet.
- TFLEX_packet: Main class to represent a TFLEX packet with methods for packet parsing and generation.

Functions:
- calc_MOD8(data, count): Calculates the MOD8 checksum of given data.
- init_FLEX(): Initializes and returns predefined FLEX packet types.
- calc_crc8(data: bytearray, count: int) -> int: Calculates the CRC8 checksum for given data.
- calc_crc16(data: bytearray, count: int) -> int: Calculates the CRC16 checksum for given data.

Usage:
The script can be used to create different types of Flex packets, parse serialized packets,
and perform checksum calculations for data integrity verification in communication systems.
"""

from enum import Enum
from typing import Tuple


class FlexPacketType(Enum):
    """
    Enumeration for different types of Flex packets.
    """
    ptObservable = 1
    ptHousekeeping = 2
    ptCommand = 3
    ptImage = 4
    ptClockFrequency = 5
    ptSync = 6

class ChecksumType(Enum):
    """
    Enumeration for different types of checksum algorithms.
    """
    MOD8 = 1
    MOD16 = 2
    MOD32 = 3
    LRC8 = 4
    LRC16 = 5
    LRC32 = 6
    CRC8 = 7
    CRC16 = 8
    CRC32 = 9

class TimeBase:
    """
    Represents a time base used in Flex packets.

    Attributes:
        ID: An identifier for the time base.
        node: The node associated with the time base.
        frequency: The frequency of the time base.
        modulo: The modulo value used in time base calculations.
        byte_count: The number of bytes representing the time base.
    """
    def __init__(self, ID: int, node: int, frequency: float, modulo: int, byte_count: int):
        self.ID = ID
        self.node = node
        self.frequency = frequency
        self.modulo = modulo
        self.byte_count = byte_count



class Entity:
    """
    Represents an entity in a Flex packet.

    Attributes:
        ID: An identifier for the entity.
        length: The length of the data associated with the entity.
        data: The data associated with the entity.
    """
    def __init__(self, ID: int, length: int, data: bytes):
        self.ID = ID
        self.length = length
        self.data = data


class TFLEX_packet:
    """
    Represents a TFLEX packet.

    Attributes:
        Various attributes representing the state and contents of the packet.
    """
    def __init__(self):
        self.capacity = 1024
        self.header_length = 0
        self.data_length = 0
        self.packet_length = 0

        self.octet = bytearray(self.capacity)

        # Initialize attributes used in the generate method
        self.PLEN = False
        self.TIME = False
        self.SRC = False
        self.DST = False
        self.STRM = False
        self.PID = False
        self.FRG = False
        self.HSK = False
        self.HVAL = False
        self.PVAL = False

        self.PLEN_bytes = 2
        self.TIME_bytes = 2
        self.SRC_bytes = 2
        self.DST_bytes = 2
        self.STRM_bytes = 2
        self.PID_bytes = 2
        self.FRG_bytes = 2
        self.HSK_bytes = 2
        self.HVAL_bytes = 2
        self.PVAL_bytes = 2
        self.XTB_length = 0

        self.header_checksum_length = 0
        self.packet_checksum_length = 0
        self.header_length = 0
        self.data_length = 0

        self.packet_length = 0
        self.pid_length = 0
        self.timestamp_length = 0
        self.freq_length = 0
        self.sync_length = 0
        self.source_length = 0
        self.destination_length = 0
        self.header_checksum_type = 0
        self.packet_checksum_type = 0
        self.fragment_address = 0
        self.timestamp = 0
        self.packet_ID = 0
        self.ATW = None

    def parse_ATW(self):
        """
        Parse the Attribute Word (ATW) of the packet to set various attribute flags.
        """
        self.PLEN = (self.ATW & 0x8000) != 0
        self.TIME = (self.ATW & 0x4000) != 0
        self.SRC = (self.ATW & 0x2000) != 0
        self.DST = (self.ATW & 0x1000) != 0
        self.STRM = (self.ATW & 0x0800) != 0
        self.PID = (self.ATW & 0x0400) != 0
        self.FRG = (self.ATW & 0x0200) != 0
        self.HSK = (self.ATW & 0x0100) != 0
        self.HVAL = (self.ATW & 0x0002) != 0
        self.PVAL = (self.ATW & 0x0001) != 0

        # Calculate size of declaration block (DCB)
        self.DCB_bits = 0
        for attribute in [self.PLEN, self.TIME, self.SRC, self.DST, self.STRM, 
                          self.PID, self.FRG, self.HSK, self.HVAL, self.PVAL]:
            if attribute:
                self.DCB_bits += 4

        # Calculate number of bytes in attribute declaration block
        self.DCB_length = self.DCB_bits // 8
        if self.DCB_bits % 8 > 0:
            self.DCB_length += 1

        # Allocate array to contain DCB
      
        

    def parse_DCB(self, serialized_packet: bytes):
        """
        Parse the Declaration Control Block (DCB) from the serialized packet.

        :param serialized_packet: The serialized packet from which to parse the DCB.
        """
        self.DCB = serialized_packet[5:5+self.DCB_length]  # start word + header_length + length ATW : ...

        position = 0
        bits = 0

        def extract_bytes():
            nonlocal position, bits
            byte_length = (self.DCB[position] >> 4) & 0x0F

            if byte_length == 0:
                byte_length = 16
            bits += 4
            self.DCB[position] = (self.DCB[position] << 4) & 0xFF
            if bits == 8:
                position += 1
                bits = 0
            return byte_length

        if self.PLEN:
            self.PLEN_bytes = extract_bytes()
            self.XTB_length += self.PLEN_bytes

        if self.TIME:
            self.TIME_bytes = extract_bytes()
            self.XTB_length += self.TIME_bytes

        if self.SRC:
            self.SRC_bytes = extract_bytes()
            self.XTB_length += self.SRC_bytes

        if self.DST:
            self.DST_bytes = extract_bytes()
            self.XTB_length += self.DST_bytes

        if self.STRM:
            self.STRM_bytes = extract_bytes()
            self.XTB_length += self.STRM_bytes

        if self.PID:
            self.PID_bytes = extract_bytes()
            self.XTB_length += self.PID_bytes

        if self.FRG:
            self.FRG_bytes = extract_bytes()
            self.XTB_length += self.FRG_bytes

        if self.HSK:
            self.HSK_bytes = extract_bytes()
            self.XTB_length += self.HSK_bytes

        if self.HVAL:
            self.HVAL_bytes = extract_bytes()
            self.XTB_length += self.HVAL_bytes

        if self.PVAL:
            self.PVAL_bytes = extract_bytes()
            self.XTB_length += self.PVAL_bytes

    def parse_XTB(self, serialized_packet: bytes):
        """
        Parse the eXtended Block (XTB) from the serialized packet.

        :param serialized_packet: The serialized packet from which to parse the XTB.
        """
        j = 0
        self.XTB = serialized_packet[5+self.DCB_length:5+self.DCB_length+self.XTB_length]   # length start word (2) + header_len (1) + length ATW (2) = 3 + length CTB : ...

        if self.PLEN:
            self.packet_length = 0
            for _ in range(self.PLEN_bytes):
                self.packet_length = (self.packet_length << 8) | self.XTB[j]      
                j += 1
        else:
            self.packet_length = self.header_length

        if self.TIME:
            self.timestamp = 0
            for _ in range(self.TIME_bytes):
                self.timestamp = (self.timestamp << 8) | self.XTB[j]
                j += 1

        if self.SRC:
            self.source = 0
            for _ in range(self.SRC_bytes):
                self.source = (self.source << 8) | self.XTB[j]
                j += 1

        if self.DST:
            self.destination = 0
            for _ in range(self.DST_bytes):
                self.destination = (self.destination << 8) | self.XTB[j]
                j += 1

        if self.STRM:
            self.stream_id = bytearray(self.STRM_bytes)
            for k in range(self.STRM_bytes):
                self.stream_id[k] = self.XTB[j]
                j += 1
        else:
            self.stream_id = bytearray([ord(ch) for ch in "NONE"])

        if self.PID:
            self.packet_id = 0
            for _ in range(self.PID_bytes):
                self.packet_id = (self.packet_id << 8) | self.XTB[j]
                j += 1

        if self.FRG:
            self.fragment_address = 0
            for _ in range(self.FRG_bytes):
                self.fragment_address = (self.fragment_address << 8) | self.XTB[j]
                j += 1

        if self.HSK:
            self.handshake = 0
            for _ in range(self.HSK_bytes):
                self.handshake = (self.handshake << 8) | self.XTB[j]
                j += 1

        if self.HVAL:
          
            self.header_checksum_type = 0
            for _ in range(self.HVAL_bytes):
                self.header_checksum_type = (self.header_checksum_type << 8) | self.XTB[j]
                j += 1
            self.header_checksum_length = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}.get(self.header_checksum_type, 0)

        if self.PVAL:
            self.packet_checksum_type = 0
            for _ in range(self.PVAL_bytes):
                self.packet_checksum_type = (self.packet_checksum_type << 8) | self.XTB[j]
                j += 1
            self.packet_checksum_length = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}.get(self.packet_checksum_type, 0)
            self.invalid = self.packet_checksum_length == 0

        self.data_length = self.packet_length - self.header_length - self.packet_checksum_length
        #self.invalid = self.invalid or (self.data_length > 512 or self.data_length < 0)


    def set_atw_bit(self, bit_position: int) -> None:
        """
        Set a specific bit in the Attribute Word (ATW) based on the given bit position.

        Parameters:
        bit_position (int): The position of the bit to be set in the ATW.
        """
        byte_index = bit_position // 8  # Determine which byte the bit is in
        bit_index = bit_position % 8    # Determine the bit's position in that byte
        self.ATW[byte_index] |= (1 << (7 - bit_index))  # Set the bit

    def generate(self) -> None:
        """
        Generate the ATW (Attribute Word), DCB (Declaration Control Block), and allocate the DCB array.
        This method sets various attributes based on the packet configuration.
        """
        '''
        Alternative - bitwise operations on integer to convert it later
        # Set the ATW based on boolean attributes
        if self.PLEN:
            self.ATW |= 0x8000
        if self.TIME:
            self.ATW |= 0x4000
        if self.SRC:
            self.ATW |= 0x2000
        if self.DST:
            self.ATW |= 0x1000
        if self.STRM:
            self.ATW |= 0x0800
        if self.PID:
            self.ATW |= 0x0400
        if self.FRG:
            self.ATW |= 0x0200
        if self.HSK:
            self.ATW |= 0x0100
        if self.HVAL:
            self.ATW |= 0x0002
        if self.PVAL:
            self.ATW |= 0x0001
        '''
                
        # Set the ATW bits based on boolean attributes

        # Initialize ATW as a bytearray of 2 bytes (16 bits)
        self.ATW = bytearray(2)

        if self.PLEN:
            self.set_atw_bit(0)  # Corresponds to 0x8000
        if self.TIME:
            self.set_atw_bit(1)  # Corresponds to 0x4000
        if self.SRC:
            self.set_atw_bit(2)  # Corresponds to 0x2000
        if self.DST:
            self.set_atw_bit(3)  # Corresponds to 0x1000
        if self.STRM:
            self.set_atw_bit(4)  # Corresponds to 0x0800
        if self.PID:
            self.set_atw_bit(5)  # Corresponds to 0x0400
        if self.FRG:
            self.set_atw_bit(6)  # Corresponds to 0x0200
        if self.HSK:
            self.set_atw_bit(7)  # Corresponds to 0x0100
        if self.HVAL:
            self.set_atw_bit(15) # Corresponds to 0x0002 (Note: This is the second-to-last bit in the 16-bit value)
        if self.PVAL:
            self.set_atw_bit(15) # Corresponds to 0x0001 (Note: This is the last bit in the 16-bit value)

        
        # Calculate the number of bits for DCB
        self.DCB_bits = 0
        for attribute in [self.PLEN, self.TIME, self.SRC, self.DST, self.STRM, self.PID, self.FRG, self.HSK, self.HVAL, self.PVAL]:
            if attribute:
                self.DCB_bits += 4

        # Calculate the number of bytes for DCB
        self.DCB_length = self.DCB_bits // 8
        if self.DCB_bits % 8 > 0:
            self.DCB_length += 1

        # Allocate the DCB array
        self.DCB = bytearray(self.DCB_length)

        # Populate the DCB array
        position = 0
        bits = 0

        for attribute, byte_size in [(self.PLEN, self.PLEN_bytes), (self.TIME, self.TIME_bytes), 
                                     (self.SRC, self.SRC_bytes), (self.DST, self.DST_bytes),
                                     (self.STRM, self.STRM_bytes), (self.PID, self.PID_bytes),
                                     (self.FRG, self.FRG_bytes), (self.HSK, self.HSK_bytes),
                                     (self.HVAL, self.HVAL_bytes), (self.PVAL, self.PVAL_bytes)]:
            if attribute:
                if byte_size == 16:  # Special case for 16 bytes
                    byte_size = 0

                # Correct bit manipulation logic
                self.DCB[position] |= (byte_size & 0x0F) << (4 - bits)
                bits += 4
                if bits == 8:
                    position += 1
                    bits = 0

        # Ensure the DCB array is properly filled

        if bits != 0:
            position += 1
        self.DCB = self.DCB[:position]  # Trim the DCB to the correct length


    def fill_xtb(self) -> None:
        """
        Fill the XTB (eXtended Block) based on the lengths of various packet attributes.
        """
        self.XTB_length = 0
        for byte_size in [self.PLEN_bytes, self.TIME_bytes, self.SRC_bytes, 
                        self.DST_bytes, self.STRM_bytes, self.PID_bytes, 
                        self.FRG_bytes, self.HSK_bytes, self.HVAL_bytes, 
                        self.PVAL_bytes]:
            self.XTB_length += byte_size

        # Initialize XTB
        self.XTB = bytearray(self.XTB_length)
        # Function to append value to XTB
        def append_to_xtb(value, byte_size):
            nonlocal xtb_index
            if byte_size == 16:  # Special case for 16 bytes
                    byte_size = 0
            for i in range(byte_size):
                self.XTB[xtb_index] = (value >> (8 * (byte_size - i - 1))) & 0xFF
                xtb_index += 1

        # Fill XTB with attribute values
        xtb_index = 0

        if self.PLEN:
            append_to_xtb(self.data_length, self.PLEN_bytes)
        if self.TIME:
            append_to_xtb(self.timestamp, self.TIME_bytes)
        if self.SRC:
            append_to_xtb(self.source, self.SRC_bytes)
        if self.DST:
            append_to_xtb(self.destination, self.DST_bytes)
        if self.STRM:
            self.XTB[xtb_index:xtb_index + self.STRM_bytes] = self.stream_id
            xtb_index += self.STRM_bytes
        if self.PID:
            append_to_xtb(self.packet_id, self.PID_bytes)
        if self.FRG:
            append_to_xtb(self.fragment_address, self.FRG_bytes)
        if self.HSK:
            append_to_xtb(self.handshake, self.HSK_bytes)
        if self.HVAL:
            append_to_xtb(self.header_checksum_type, self.HVAL_bytes)
        if self.PVAL:
            append_to_xtb(self.packet_checksum_type, self.PVAL_bytes)

        # Ensure the XTB array is trimmed to the correct length
        self.XTB = self.XTB[:xtb_index]


    def decode_flex_packet(self, serialized_packet: bytearray) -> Tuple[bytes, bool]:
        """
        Decode a serialized FLEX packet and verify its checksums.

        Parameters:
        serialized_packet (bytearray): The serialized packet to be decoded.

        Returns:
        Tuple[bytes, bool]: The extracted data from the packet and the result of the checksum verification.
        """
        # Split the serialized packet into its components
        # Assuming the structure of the packet is known

        self.header_length = serialized_packet[2]
        self.ATW = int.from_bytes(serialized_packet[3:5],byteorder='big') # start_word + header_len ....
        self.parse_ATW()
        self.parse_DCB(serialized_packet)
        self.parse_XTB(serialized_packet)

        data = serialized_packet[self.header_length:self.header_length + self.packet_length]

        checks = self.verify_checksums(serialized_packet)
        
        return data,checks

    def verify_checksums(self, serialized_packet: bytearray) -> bool:
        """
        Verify the checksums of a serialized FLEX packet.

        Parameters:
        serialized_packet (bytearray): The serialized packet whose checksums are to be verified.

        Returns:
        bool: True if checksums are valid, False otherwise.
        """
        # Recalculate the header checksum
        header_checksum = serialized_packet[self.header_length+self.packet_length:self.header_length+self.packet_length+2]

        data_checksum = serialized_packet[self.header_length+self.packet_length+2:self.header_length+self.packet_length+4]

        recalculated_header_checksum = calc_crc16(serialized_packet[:self.header_length], len(serialized_packet[:self.header_length]))

        recalculated_data_checksum = calc_crc16(serialized_packet[self.header_length:], self.packet_length)

        # Compare with received checksums
        if recalculated_header_checksum != int.from_bytes(header_checksum, 'big'):
            print('wrong header')
            return False

        if recalculated_data_checksum != int.from_bytes(data_checksum, 'big'):
            print('wrong data')
            return False
        
        return True

    def add(self, aCipher):
        if self.octet_count == self.capacity:
            self.capacity += 1024
            self.octet.extend([0] * 1024)  # Increase the size of the octet list
        self.octet[self.octet_count] = aCipher
        self.octet_count += 1          

def calc_MOD8(data, count):
    return sum(data[:count]) % 256

def init_FLEX():
  
    PacketTypes = []

    # Packet type definition for the MMC/SD card
    SD_packet = TFLEX_packet()
    SD_packet.PLEN = True
    SD_packet.HSK = False  # no handshake
    SD_packet.SRC = False  # no source
    SD_packet.DST = False  # no destination
    SD_packet.PID = True   # 16 bit packet ID
    SD_packet.TIME = True  # 32 bit data
    SD_packet.HVAL = True  # CRC-16 for data block
    SD_packet.PVAL = True  # CRC-16 for data block
    SD_packet.generate()
    PacketTypes.append(SD_packet)

    # Packet type definition for simple telemetry
    TEL_packet = TFLEX_packet()
    TEL_packet.PLEN = True  # flexible data block length (16 Bit)
    TEL_packet.TIME = True  # 16 bit timestamp
    TEL_packet.SRC = True   # 1 byte source
    TEL_packet.DST = True   # 1 byte destination
    TEL_packet.PID = True   # 16 bit packet counter
    TEL_packet.HSK = True   # request ACK
    TEL_packet.HVAL = True  # header data checksum
    TEL_packet.PVAL = True  # packet data checksum
    TEL_packet.generate()
    PacketTypes.append(TEL_packet)

    return SD_packet, TEL_packet, PacketTypes

def calc_crc8(data: bytearray, count: int) -> int:
    """
    Calculate the CRC8 for a given bytearray and count.

    Parameters:
    data (bytearray): Input data as a bytearray object.
    count (int): The number of bytes in the data to consider for CRC calculation.

    Returns:
    int: The calculated CRC8 as an integer.
    """
    crc8 = 0

    if 0 < count <= len(data):
        for byte in data[:count]:
            crc8 ^= byte
            for _ in range(8):
                test8 = crc8 & 0x80
                crc8 = (crc8 << 1) & 0xFF  # Ensure CRC remains within 8 bits
                if test8 != 0:
                    crc8 ^= 0x31  # Polynomial used in the CRC calculation

    return crc8

def calc_crc16(data: bytearray, count: int) -> int:
    """
    Calculate the CRC16 for a given bytearray and count.

    Parameters:
    data (bytearray): Input data as a bytearray object.
    count (int): The number of bytes in the data to consider for CRC calculation.

    Returns:
    int: The calculated CRC16 as an integer.
    """
    crc16 = 0

    if 0 < count <= len(data):
        for i in range(count):
            aByte = data[i] << 8
            crc16 ^= aByte
            for _ in range(8):
                test16 = crc16 & 0x8000
                crc16 = (crc16 << 1) & 0xFFFF  # Ensure CRC remains within 16 bits
                if test16 != 0:
                    crc16 ^= 0x8005  # Polynomial used in the CRC calculation

    return crc16
