# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)


import socket
import sys
from struct import *

import matplotlib.pyplot as plt


ip_tcp_packets = []
ip_udp_packets = []
ip_icmp_packets = []
ip_other_packets = []

_is_running = True

# Convert a string of 6 characters of ethernet address into a dash separated hex string


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]),
                                           ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))

    return b


def loop():
    # create a AF_PACKET type raw socket (thats basically packet level)
    # define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.ntohs(0x0003))
    except socket.error as msg:
        print ('Socket could not be created. Error Code : ' +
               str(msg.errno) + ' Message ' + msg.strerror)
        sys.exit()

    counter = 0
    # receive a packet
    while _is_running:

        packet = s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        # print ('Destination MAC : ' + str(packet[0:6]) + ' Source MAC : ' + eth_addr(
        #     str(packet[6:12])) + ' Protocol : ' + str(eth_protocol))

        dict_packet = {'destination_mac': eth_addr(str(packet[0:6])),
                       'source_mac': eth_addr(str(packet[6:12])),
                       'eth_protocol': eth_protocol}

        # Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            dict_packet['eth_protocol'] = "IPs"
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) +
            #        ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
            dict_packet['version'] = version
            dict_packet['ip_header_length'] = ihl
            dict_packet['ttl'] = ttl
            dict_packet['ip_protocol'] = protocol

            dict_packet['source_address'] = s_addr
            dict_packet['destination_address'] = d_addr

            # TCP protocol
            if protocol == 6:

                dict_packet['ip_protocol'] = "TCP"
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                # now unpack them :)
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                # print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' +
                #        str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

                dict_packet['source_port'] = source_port
                dict_packet['destination_port'] = dest_port
                dict_packet['sequence'] = sequence
                dict_packet['acknowledgement'] = acknowledgement
                dict_packet['tcp_header_lenght'] = tcph_length

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                # print ('Data : ' + data)

                ip_tcp_packets.append(dict_packet)

            # ICMP Packets
            elif protocol == 1:
                dict_packet['ip_protocol'] = "ICMP"
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                # now unpack them :)
                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                # print ('Type : ' + str(icmp_type) + ' Code : ' +
                #        str(code) + ' Checksum : ' + str(checksum))

                dict_packet['type'] = icmp_type
                dict_packet['code'] = code
                dict_packet['checksum'] = checksum

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                # print ('Data : ' + data)
                ip_icmp_packets.append(dict_packet)

            # UDP packets
            elif protocol == 17:
                dict_packet['ip_protocol'] = "UDP"
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                # now unpack them :)
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                # print ('Source Port : ' + str(source_port) + ' Dest Port : ' +
                #        str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))

                dict_packet['source_port'] = source_port
                dict_packet['destination_port'] = dest_port
                dict_packet['length'] = length
                dict_packet['checksum'] = checksum

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]

                # print ('Data : ' + data)
                ip_udp_packets.append(dict_packet)

            # some other IP packet like IGMP
            else:
                dict_packet['ip_protocol'] = "Not TCP/UDP/ICMP"
                ip_other_packets.append(dict_packet)
                # print ('Protocol other than TCP/UDP/ICMP')

        else:
            ip_other_packets.append(dict_packet)
        # counter += 1
        # if counter == 500:

        #     protocol_names = ["TCP", "UDP", "ICMP", "Other"]
        #     amount_of_packets = [len(ip_tcp_packets), len(
        #         ip_udp_packets), len(ip_icmp_packets), len(ip_other_packets)]

        #     plt.bar(protocol_names, amount_of_packets)
        #     plt.ylabel('Protocols')
        #     plt.suptitle('Ammount of packets per protocol')
        #     plt.show()
        #     counter = 0

        # print
# loop()
