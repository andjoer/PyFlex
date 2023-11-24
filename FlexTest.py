"""
NMEA to Flex Packet Conversion Script

This script demonstrates the use of the flex.py module to handle Flex packets in a communication system. 
It includes functions to encode NMEA messages to bytearrays, fill TFLEX_packet objects with encoded data, 
serialize these packets, and convert NMEA messages into serialized TFLEX_packets. The script primarily 
serves as an example to validate the main structure and functionality of the flex.py module.

The script also includes sample usage and demonstrations of encoding and decoding processes, along with 
examples of handling both correct and corrupted Flex packets.

Functions:
- encode_nmea_data(nmea_message: str) -> ByteString: Encodes a NMEA message to a bytearray.
- fill_flex_packet(flex_packet: TFLEX_packet, encoded_data: ByteString) -> None: Fills a TFLEX_packet with encoded data.
- serialize_flex_packet(flex_packet: TFLEX_packet) -> ByteString: Serializes a TFLEX_packet into a bytearray.
- convert_nmea_to_flex(nmea_message: str) -> ByteString: Converts a NMEA message to a serialized TFLEX_packet.

Usage:
The script can be directly run to see examples of converting NMEA messages to Flex packets, serializing them, 
and verifying their integrity through checksums. It demonstrates the process with both correct and intentionally 
corrupted data to show the robustness of the packet handling.

Note:
The script relies on the flex.py module, which should be available in the same environment for successful execution.
"""


from typing import ByteString
from  Flex import TFLEX_packet, calc_crc16

def encode_nmea_data(nmea_message: str) -> ByteString:
    """
    Encode a NMEA message into a bytearray using UTF-8 encoding.

    Parameters:
    nmea_message (str): The NMEA message to be encoded.

    Returns:
    ByteString: A bytearray representation of the encoded NMEA message.
    """
    return bytearray(nmea_message, 'utf-8')

def fill_flex_packet(flex_packet: TFLEX_packet, encoded_data: ByteString) -> None:
    """
    Fill a TFLEX_packet object with encoded data, and set necessary packet attributes.

    Parameters:
    flex_packet (TFLEX_packet): The TFLEX_packet object to be filled.
    encoded_data (ByteString): The encoded data to be added to the packet.

    This function does not return anything.
    """
    flex_packet.data_length = len(encoded_data)
    if flex_packet.data_length > flex_packet.capacity:
        flex_packet.capacity = flex_packet.data_length
        flex_packet.octet = bytearray(flex_packet.capacity)

    flex_packet.octet[:flex_packet.data_length] = encoded_data

    # Setting standard packet attributes for this example
    flex_packet.PLEN = True
    flex_packet.TIME = False
    flex_packet.SRC = False
    flex_packet.DST = False
    flex_packet.PID = False
    flex_packet.HSK = False
    flex_packet.HVAL = False
    flex_packet.PVAL = False

    # Generate ATW, set DCB and XTB lengths, and calculate header length
    flex_packet.generate()
    flex_packet.fill_xtb()
    flex_packet.header_length = 3 + len(flex_packet.ATW) + len(flex_packet.DCB) + len(flex_packet.XTB)

def serialize_flex_packet(flex_packet: TFLEX_packet) -> ByteString:
    """
    Serialize a TFLEX_packet object into a bytearray.

    Parameters:
    flex_packet (TFLEX_packet): The TFLEX_packet object to be serialized.

    Returns:
    ByteString: The serialized packet as a bytearray.
    """
    serialized_packet = bytearray()
    start_word = bytearray([0xF1, 0xE0])
    serialized_packet.extend(start_word)
    serialized_packet.extend(flex_packet.header_length.to_bytes(1, 'big'))
    serialized_packet.extend(flex_packet.ATW)
    serialized_packet.extend(flex_packet.DCB)
    serialized_packet.extend(flex_packet.XTB)
    serialized_packet.extend(flex_packet.octet[:flex_packet.data_length])

    header_checksum = calc_crc16(serialized_packet[:flex_packet.header_length], len(serialized_packet[:flex_packet.header_length]))
    data_checksum = calc_crc16(serialized_packet[flex_packet.header_length:], len(serialized_packet[flex_packet.header_length:]))
    serialized_packet.extend(header_checksum.to_bytes(2, 'big'))
    serialized_packet.extend(data_checksum.to_bytes(2, 'big'))

    return serialized_packet

def convert_nmea_to_flex(nmea_message: str) -> ByteString:
    """
    Convert a NMEA message to a serialized TFLEX_packet.

    Parameters:
    nmea_message (str): The NMEA message to be converted.

    Returns:
    ByteString: The serialized TFLEX_packet as a bytearray.
    """
    flex_packet = TFLEX_packet()
    encoded_data = encode_nmea_data(nmea_message)
    fill_flex_packet(flex_packet, encoded_data)
    return serialize_flex_packet(flex_packet)


###############################

#examples

###############################

if __name__ == '__main__':
    nmea_message = "$RQIMU0,000008.3784,-2050.,15.000,-28.00,-22.66,5.6250,8.3750,60.0000,468.00,-356.0*5A"
    flex_binary = convert_nmea_to_flex(nmea_message)
    print('len of bin')
    print(len(flex_binary))

    print((flex_binary))

    decoded_packet = TFLEX_packet()
    print(decoded_packet.decode_flex_packet(flex_binary))   #prints data, checksum-check
    #correct_binary:
    flex_binary_correct = bytearray(b'\xf1\xe0\x08\x80\x00 \x00V$RQIMU0,000008.3784,-2050.,15.000,-28.00,-22.66,5.6250,8.3750,60.0000,468.00,-356.0*5A\x03z\xad\xd1')

    #corrupted binary data

    flex_binary_corrupt = bytearray(b'\xf1\xe0\x08\x80\x00 \x00V$RQIMU0,000007.3784,-2050.,15.000,-28.00,-22.66,5.6250,8.3750,60.0000,468.00,-356.0*5A\x03z\xad\xd1')

    decoded_packet_corrupt = TFLEX_packet()
    print(decoded_packet_corrupt.decode_flex_packet(flex_binary_corrupt))   #prints data, checksum-check

    #corrupted binary header

    flex_binary_corrupt = bytearray(b'\xf1\xe0\x08\x80\x00 \x00V$RQIMU0,000007.3784,-2050.,15.000,-28.00,-22.66,5.6250,8.3750,60.0000,468.00,-356.0*5A\x03z\xad\xd1')

    decoded_packet_corrupt = TFLEX_packet()
    print(decoded_packet_corrupt.decode_flex_packet(flex_binary_corrupt))   #prints data, checksum-check

    flex_binary_corrupt = bytearray(b'\xf1\xe1\x08\x80\x00 \x00V$RQIMU0,000008.3784,-2050.,15.000,-28.00,-22.66,5.6250,8.3750,60.0000,468.00,-356.0*5A\x03z\xad\xd1')

    decoded_packet_corrupt = TFLEX_packet()
    print(decoded_packet_corrupt.decode_flex_packet(flex_binary_corrupt))   #prints data, checksum-check
