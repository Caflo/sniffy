import os
import argparse
import argparse
import os
import struct
import sys
import logging
import socket
import pickle
import time
from src.log.log import logger
from src.controller.sniffy_server import BUFSIZE_MSG, BUFSIZE_FILE, INT_SIZE, RequestHandlerServer

def parse_options(parser):

    # top-level parser

    subparsers = parser.add_subparsers(help="Manage sniffers", dest='cmd')

    # parse sub-commands
    sp1 = subparsers.add_parser('init-server', help='Init sniffy server.')

    sp2 = subparsers.add_parser('stop-server', help='Stop sniffy server.')

    sp3 = subparsers.add_parser("add", help='Add a sniffer on an interface.')
    sp3.add_argument('interface', action='store', default='', type=str)
    sp3.add_argument('--dynamic', dest='dynamic', action='store_true', default=False)

    subparsers.add_parser("remove", help='Remove a sniffer with given ID.')\
            .add_argument('sniffer_id', action='store', type=int)

    subparsers.add_parser('clear-all', help='Clear all sniffers.')

    subparsers.add_parser('start', help='Start capturing on sniffer with given ID.')\
            .add_argument('sniffer_id', action='store', type=int) 

    subparsers.add_parser('stop', help='Stop capturing on sniffer with given ID.')\
            .add_argument('sniffer_id', action='store', type=int) 

    subparsers.add_parser('start-all', help='Start all sniffers.')

    subparsers.add_parser('stop-all', help='Stop all sniffers.')
    
    sp4 = subparsers.add_parser('schedule', help='Schedule capturing on sniffer with given ID.')
    sp4.add_argument('--from', dest='_from', action='store', type=str)
    sp4.add_argument('--to', dest='_to', action='store', type=str)
    sp4.add_argument('--interval', dest='interval', action='store', type=int)

    subparsers.add_parser('get-all', help='Get all sniffers.')

    subparsers.add_parser('get-active', help='Get all active sniffers.')

    subparsers.add_parser('list-ifaces', help='List all network interfaces.')

    subparsers.add_parser('dump-stats', help='Dump network statistics on sniffer with given ID.')\
            .add_argument('sniffer_id', action='store', type=int) 

    parser.add_argument('--host', dest='host', action='store', default='127.0.0.1', type=str, help='Set host on which connect/setup server.') 
    
    parser.add_argument('--port', dest='port', action='store', default=61000, type=int, help='Set port on which connect/setup server.') 
    
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False, help='Enable verbosity.') 

    args = parser.parse_args()

  
    return args

if __name__ == "__main__":

  description = ""
  with open("README.md", 'r') as f:
    description = f.readline()

  # Initializing parser
  parser = argparse.ArgumentParser(description=description)
  args = parse_options(parser)

  if args.cmd == None:
    parser.print_help()
    exit()

  # Getting shared logger
  logger = logging.getLogger("sniffy")
  logger.disabled = not args.verbose
  logger.info(f"input cmd: '{args.cmd}'")


  # setup server
  if args.cmd == 'init-server':
    rhs = RequestHandlerServer()
    rhs.init_server(args.host, args.port)
    exit()

  # otherwise, send cmd to server
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s_data = pickle.dumps(args)
    s.connect((args.host, args.port))
    logger.info(f"Connected to {args.host}:{args.port}. Sending command...")
    s.sendall(s_data)

    # receive results
    if args.cmd == 'start-all':
      num_msg = struct.unpack('!i', s.recv(INT_SIZE))[0] 
      for i in range(num_msg):
        len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
        msg = s.recv(len).decode() # receive status msg
        print(msg)


    if args.cmd == 'start': 
      len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
      msg = s.recv(len).decode() # receive status msg
      print(msg)


    if args.cmd == 'stop-all': # prepare to receive multiple pcap files after stopping 
        num_pcap = struct.unpack('!i', s.recv(INT_SIZE))[0] # receive number of pcap to get
        print(f"Files to receive: {num_pcap}")
        for i in range(0, num_pcap):
            len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
            msg = s.recv(len).decode() # receive status msg
            print(msg)

            len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
            pcap_filename = s.recv(len).decode() # receive filename
            print(pcap_filename)

            total_size = struct.unpack('!i', s.recv(INT_SIZE))[0] # receive filesize

            # receive file chunk by chunk
            f = open(pcap_filename, 'wb')
            nread = 0
            while (nread != total_size):
              len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
              data = s.recv(len)
              f.write(data)
              nread += len
            f.close()

            term = s.recv(1)  # seq terminator

            f.close()
            print(f"Pcap retrieved: {pcap_filename}") 

    if args.cmd == 'stop': # prepare to receive pcap file after stopping 
        len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
        msg = s.recv(len).decode() # receive status msg
        print(msg)

        len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
        pcap_filename = s.recv(len).decode() # receive filename
        print(pcap_filename)

        total_size = struct.unpack('!i', s.recv(INT_SIZE))[0] # receive filesize

        # receive file chunk by chunk
        f = open(pcap_filename, 'wb')
        nread = 0
        while (nread != total_size):
          len = struct.unpack('!i', s.recv(INT_SIZE))[0] 
          data = s.recv(len)
          f.write(data)
          nread += len
        f.close()

        term = s.recv(1)  # seq terminator

        f.close()
        print(f"Pcap retrieved: {pcap_filename}") 

    else: # just get the status message
        msg = s.recv(BUFSIZE_MSG).decode()
        print(msg)

    # Eventually close socket
    s.close()

##      n_pcap = s_file.readline()
##      for i in range(0, n_pcap):
#      pcap_absfilename = s_file.readline()
#      while pcap_absfilename:
#        pcap_absfilename = pcap_absfilename[:len(pcap_absfilename) - 1] # removing '\n'
#        pcap_filename = os.path.basename(pcap_absfilename)
#        f = open(pcap_filename, 'wb')
#        logger.info(f"Receiving pcap file ({pcap_filename})...")
#        raw_data = s.recv(CHUNKSIZE)
#        while raw_data:
#          f.write(raw_data)
#          raw_data = s.recv(CHUNKSIZE)
#        f.close()
#        print(f"Pcap retrieved: {pcap_filename}") 
#        pcap_absfilename = s_file.readline()
## ---- 
#    s_file.close()
