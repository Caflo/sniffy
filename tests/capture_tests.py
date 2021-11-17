import os
import logging
import unittest
import time
from src.log.log import logger
from unittest import TestCase
from src.controller.sniffy_server import RequestHandlerServer
import subprocess
from src.controller.utils import cleanup_files

class TestCapture(TestCase):

    def setUp(self) -> None:
        print("\n\n----------------- SETUP -----------------")
        print("Getting shared logger")
        self.logger = logging.getLogger("sniffy.capture_tests")
        logger.info("Cleaning up...")
        subprocess.call(['tests\\restore_resources.bat'])

    # TODO cleanup generated PCAP files        

    def test_01_sniff(self):
        print("\n\n----------------- TEST 01: SNIFF ON GIVEN INTERFACE -----------------")
        self.cf = RequestHandlerServer(config_path='tests/resources', config_filename='sniffers_05.json', pcap_path='tests/')

        self.cf.add_sniffer("Realtek RTL8821CE 802.11ac PCIe Adapter")
        self.cf.read_sniffers()

        self.cf.start_sniffer(1)
        time.sleep(5)

        self.cf.add_sniffer("Realtek RTL8821CE 802.11ac PCIe Adapter")

        self.cf.start_sniffer(2)
        time.sleep(5)
        self.cf.stop_sniffer(2)
        self.cf.stop_sniffer(1)

        logger.info("Cleaning up pcap files...")
        cleanup_files('tests/', 'task_[0-9].pcap')


if __name__ == '__main__':
    unittest.main()