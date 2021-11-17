import socket
import struct
import binascii
from scapy.all import *

class ThreadHandler:
    def __init__(self, pcap_path=None) -> None:
        self.thread_queue = list(dict())
        self.logger = logging.getLogger('pcapture')

    def start_sniffer(self, sniffer_task, pcap_path=None):
        self.logger.info(f"Starting sniffer with ID = {sniffer_task.id}")

        def process(id: int, pcap_abs_filename: str):
            def process_packet(pkt):
                wrpcap(pcap_abs_filename, pkt, append=True)

            return process_packet
        if sniffer_task.dynamic:
            self.logger.info(f"Sniffing mode: dynamic")
            t = AsyncSniffer(iface=sniffer_task.iface, prn=process(sniffer_task.id, pcap_path)) # appending pcap file live while sniffing
        else:
            self.logger.info(f"Sniffing mode: static")
            t = AsyncSniffer(iface=sniffer_task.iface) # silent
        entry = {
            "task_id": sniffer_task.id,
            "thread": t
        }
        t.start()
        self.thread_queue.append(entry)
        return t.thread.ident
        
    def stop_sniffer(self, sniffer_task):
        self.logger.info(f"Stopping sniffer with ID = {sniffer_task.id}")
        entry = self.__get_thread_by_sniffer_id(sniffer_task)
        pkts = entry['thread'].stop()
        self.thread_queue.remove(entry)
        return pkts

    def schedule_sniffer(self, sniffer_id):
        raise NotImplementedError()

    def __get_thread_by_sniffer_id(self, sniffer_task):
        for entry in self.thread_queue:
            if entry['task_id'] == sniffer_task.id:
                return entry

