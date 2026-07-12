import socket
import struct

def calculate_checksum(data):

    if len(data) % 2:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF


def make_pseudo_header(src_ip, dst_ip, tcp_length):
    return struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_length)


def tcp_header(src_ip, dst_ip, dst_port):
    payload = "Hello! Tcp Packet ".encode()
    src_port = 8090
    seq_number = 10001
    ack_number = 0
    data_offset = 5
    reserved = 0
    flags = 0x002  
    offset_reserved_flags = (data_offset << 12) | (reserved << 9) | flags
    window_size = 56535
    urg_pointer = 0

    header = struct.pack("!HHIIHHHH",
                     src_port,
                     dst_port,
                     seq_number,
                     ack_number,
                     offset_reserved_flags,
                     window_size,
                     0,              #initial checksums
                     urg_pointer)

    tcp_length = len(header) + len(payload)
    pseudo_header = make_pseudo_header(src_ip, dst_ip, tcp_length)

    checksum_data = pseudo_header + header + payload
    checksum = calculate_checksum(checksum_data)

    header = struct.pack("!HHIIHHHH",
                     src_port,
                     dst_port,
                     seq_number,
                     ack_number,
                     offset_reserved_flags,
                     window_size,
                     checksum,       
                     urg_pointer)

    packet = header + payload
    return packet


def main():
    src_ip = "10.10.10.2"     
    dst_ip = "8.8.8.8"
    dst_port = 8090

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as tcp_socket:
            packet = tcp_header(src_ip, dst_ip, dst_port)
            tcp_socket.sendto(packet, (dst_ip, dst_port))
            print(f"Packet has been sent to {dst_ip}:{dst_port}")
    except PermissionError:
        print("You need root permission to send this packet")
    except Exception as Error:
        print(Error)


if __name__ == "__main__":
    main()
