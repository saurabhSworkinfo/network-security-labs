import socket
import struct


def calculate_checksum(data):
    if len(data) % 2:
        data += b'\x00'

    checksum = 0

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)

    checksum = ~checksum & 0xffff

    if checksum == 0:
        checksum = 0xFFFF

    return checksum


def make_pseudo_header(src_ip, dst_ip, udp_length):
    return struct.pack(
        '!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_UDP,
        udp_length
    )


def udp_packet(src_ip, dst_ip, dst_port, src_port=9090):
    payload = b"hello! UDP Packet !"

    udp_length = 8 + len(payload)

    udp_header = struct.pack(
        '!HHHH',
        src_port,
        dst_port,
        udp_length,
        0
    )

    pseudo_header = make_pseudo_header(src_ip, dst_ip, udp_length)

    checksum = calculate_checksum(pseudo_header + udp_header + payload)

    udp_header = struct.pack(
        '!HHHH',
        src_port,
        dst_port,
        udp_length,
        checksum
    )

    return udp_header + payload


def main():
    src_ip = "10.10.10.2"    # virtual machine ip 
    dst_ip = "8.8.8.8"
    dst_port = 9091

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as udp_socket:
            packet = udp_packet(src_ip, dst_ip, dst_port)
            udp_socket.sendto(packet, (dst_ip, dst_port))
            print(f"Packet has been sent to {dst_ip}:{dst_port}")
    except PermissionError:
        print("You need root permission to send this packet")
    except Exception as Error:
        print(Error)


if __name__ == "__main__":
    main()
