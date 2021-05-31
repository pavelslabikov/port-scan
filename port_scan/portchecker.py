import socket
from multiprocessing.pool import ThreadPool

from port_scan import packets

CHUNK_SIZE = 1024
PACKETS = [packets.DNS_PACKET, packets.EMPTY_PACKET]


class PortChecker:
    def __init__(self, host: str, is_udp: bool, is_tcp: bool, ports: tuple):
        self.hostname = socket.gethostbyname(host)
        self.udp_checked = is_udp
        self.tcp_checked = is_tcp
        self.ports = [int(p) for p in ports]
        self.thread_pool = ThreadPool(processes=10)

    def start_scanning(self):
        try:
            tasks = []
            for port in range(self.ports[0], self.ports[1] + 1):
                if self.tcp_checked:
                    tcp_task = self.thread_pool.apply_async(self.check_port, args=(port, "TCP"))
                    tasks.append(tcp_task)
                if self.udp_checked:
                    udp_task = self.thread_pool.apply_async(self.check_port, args=(port, "UDP"))
                    tasks.append(udp_task)
            for task in tasks:
                task.wait()
        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()

    def check_port(self, port: int, port_proto: str):
        if port_proto == "UDP":
            with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                sock.settimeout(0.5)
                for packet in PACKETS:
                    try:
                        sock.sendto(packet, (self.hostname, port))
                        data, _ = sock.recvfrom(2048)
                        print(f"{port_proto}: {port}")
                        break
                    except socket.error:
                        pass

        else:
            with (socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((self.hostname, port))
                    print(f"{port_proto}: {port}")
                except socket.error:
                    pass
