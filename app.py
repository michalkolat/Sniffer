import socket, sys
from struct import *
import csv
from statistics_row import StatisticsRow


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def create_connection():
    try:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print('Polaczenie nie moglo zostac utworzone : ' + str(msg[0]) + ' Blad: ' + msg[1])
        sys.exit()


def handle_packet(connection):
    global statistics_row, statistics_row
    packet = connection.recvfrom(65565)
    statistics_row = StatisticsRow()

    # podzial pakietu
    packet = packet[0]
    # pobranie naglowka
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    statistics_row.dest_ip = eth_addr(packet[0:6])
    statistics_row.source_ip = eth_addr(packet[6:12])
    statistics_row.protocol = str(eth_protocol)
    statistics_row.packet_size = str(len(packet))
    print('Odbiorca : ' + eth_addr(packet[0:6]) + ' Nadawca : ' + eth_addr(packet[6:12]) + ' Protokol : ' + str(
        eth_protocol))
    # protokol egp glowny
    if eth_protocol == 8:

        # pobranie danych pakietu i podzial
        ip_header = packet[eth_length:20 + eth_length]

        # odpakowanie naglowka
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print('Wersja : ' + str(version) + ' Dlugosc naglowka : ' + str(ihl) + ' TTL : ' + str(
            ttl) + ' Protokol : ' + str(protocol) + ' Nadawca : ' + str(s_addr) + ' Odbiorca : ' + str(d_addr))

        # protokol TCP
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            statistics_row.source_port = source_port

            dest_port = tcph[1]
            statistics_row.dest_port = dest_port

            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print('Port zrodlowy : ' + str(source_port) + ' Port docelowy : ' + str(
                dest_port) + ' Numer sekwencyjny : ' + str(sequence) + ' Numer potwierdzanego bajtu : ' + str(
                acknowledgement) + ' Dlugosc naglowka : ' + str(tcph_length))

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # payload
            data = packet[h_size:]

            print('Dane : ' + data)

        # pakiety ping ICMP
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]

            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print('Typ : ' + str(icmp_type) + ' Kod : ' + str(code) + ' Suma kontrolna : ' + str(checksum))

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            # payload
            data = packet[h_size:]

            print('Dane przechwycone : ' + data)

        # pakiet udp
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]

            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print('Port zrodlowy : ' + str(source_port) + ' Port docelowy : ' + str(
                dest_port) + ' Dlugosc naglowka : ' + str(length) + ' Suma kontrolna : ' + str(checksum))

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            # payload
            data = packet[h_size:]

            print('Dane przechwycone : ' + data)

        # inny pakiet
        else:
            print('Inny protokol, mozliwe szyfrowanie')

        print('koniec pakietu')
    return statistics_row


with open('statistics.csv', mode='w') as statistics_file:
    employee_writer = csv.writer(statistics_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    connection = create_connection()
    while True:
        statistics_row = handle_packet(connection)
        employee_writer.writerow(
            [statistics_row.time, statistics_row.protocol, statistics_row.source_ip, statistics_row.source_port,
             statistics_row.dest_ip, statistics_row.dest_port, statistics_row.packet_size])

# odbior ramki danych golego pakietu
