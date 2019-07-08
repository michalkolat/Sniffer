import time


class StatisticsRow:
    time = int(time.time())
    source_ip = None
    dest_ip = None
    source_port = None
    dest_port = None
    protocol = None
    packet_size = None
