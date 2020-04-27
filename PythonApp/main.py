import netifaces
import pcapy

from scapy.all import *


def print_mac_addr(pdata):
    print(
        "MAC Address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            pdata[0], pdata[1], pdata[2], pdata[3], pdata[4], pdata[5]
        )
    )


def print_ip_addr(pdata):
    print("{}.{}.{}.{}".format(pdata[0], pdata[1], pdata[2], pdata[3]))


def print_p_data(packet_data):
    data_len = min(len(packet_data), 10)
    for i in range(data_len):
        print("{:02X} ".format(packet_data[i]), end="")
    print()


def print_interface_list():
    interfaces = netifaces.interfaces()
    print("Available interfaces:")
    for interface in interfaces:
        print(interface)


def select_interface():
    interfaces = netifaces.interfaces()
    print("Available interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"{i}. {interface}")
    while True:
        try:
            choice = int(input("Enter the interface number: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("Invalid interface number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def main():
    print_interface_list()
    dev = select_interface()

    try:
        cap = pcapy.open_live(dev, 65536, True, 1000)
        while True:
            (header, packet) = cap.next()
            process_packet(packet)
    except Exception as e:
        print("Error capturing packets:", str(e))


def process_packet(packet):
    print("===============================")
    print(" {} Bytes captured".format(len(packet)))

    eth = Ether(packet)
    print(" Source")
    print_mac_addr(eth.src)

    print(" Destination")
    print_mac_addr(eth.dst)

    if eth.type == 0x0800:  # IPv4
        ip = IP(packet[14:])
        if ip.version == 4:  # IPv4
            print(" Source IP Address:")
            print_ip_addr(ip.src)
            print(" Destination IP Address:")
            print_ip_addr(ip.dst)

            if ip.proto == 6:  # TCP
                tcp = TCP(packet[14 + ip.ihl * 4 :])
                print(" Source Port Number:", tcp.sport)
                print(" Destination Port Number:", tcp.dport)

                tcp_data_len = len(packet) - 14 - ip.ihl * 4 - tcp.dataofs * 4
                print(" TCP Data Length:", tcp_data_len)
                if tcp_data_len > 0:
                    print(" Print Data:")
                    print_p_data(packet[14 + ip.ihl * 4 + tcp.dataofs * 4 :])


if __name__ == "__main__":
    main()
