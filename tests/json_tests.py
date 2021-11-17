import os
import logging
import unittest
import subprocess
from src.log.log import logger
from unittest import TestCase
from src.controller.sniffer_ctrl import RequestHandler

class TestJson(TestCase):

    def setUp(self) -> None:
        print("\n\n----------------- SETUP -----------------")
        print("Getting shared logger")
        self.logger = logging.getLogger("sniffy.json_tests")
        logger.info("Cleaning up...")
        subprocess.call(['tests\\restore_resources.bat']) # TODO do a better cross-platform way to restore files


    def test_01_read_sniffers(self):
        print("\n\n----------------- TEST 01: GET ALL SNIFFERS / GET ACTIVE SNIFFERS -----------------")
        self.cf = RequestHandler(config_path='tests/resources', config_filename='sniffers_01.json')
        self.cf.get_all_sniffers()
        self.cf.get_active_sniffers()

    def test_02_add_sniffer(self):
        print("\n\n----------------- TEST 02: ADD SNIFFER -----------------")
        self.cf = RequestHandler(config_path='tests/resources', config_filename='sniffers_02.json')
        self.cf.add_sniffer("iface-test-4")
        self.cf.get_all_sniffers()

    def test_03_remove_sniffer(self):
        print("\n\n----------------- TEST 03: REMOVE SNIFFER -----------------")
        self.cf = RequestHandler(config_path='tests/resources', config_filename='sniffers_03.json')
        self.cf.get_all_sniffers()
        self.cf.remove_sniffer(2)

    def test_04_clear_all_sniffers(self):
        print("\n\n----------------- TEST 03: CLEAR ALL SNIFFERS -----------------")
        self.cf = RequestHandler(config_path='tests/resources', config_filename='sniffers_04.json')
        self.cf.clear_all_sniffers()
        self.cf.get_all_sniffers()



if __name__ == '__main__':
    unittest.main()