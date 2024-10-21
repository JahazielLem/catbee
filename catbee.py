import argparse
import os
import sys
import logging
import binascii
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.config import conf
from modules.utils import UsageError, fmt_addr_to_hex
from modules.jammer import Jammer
from modules.catsniffer import Sniffer, TISnifferPacket, SNIFFER_DEF_CHANNEL
from modules.packets import is_association_response, is_disassociation_request

conf.dot15d4_protocol = "zigbee"

SCRIPT_NAME = os.path.basename(sys.argv[0])
logging.basicConfig(
    handlers=[logging.FileHandler("catbee.log"), logging.StreamHandler()],
    level="WARNING",
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

class CatBee:
  def __init__(self):
    self.parser = argparse.ArgumentParser(description='CatBee: A tool to actionate a Jammer with a CatSniffer as sniffer',
                                          usage='%(prog)s [options]', epilog="Happy Hacking :)")
    self.parser.add_argument('-cs', '--catsniffer', type=str, help='Serial path to the CatSniffer')
    self.parser.add_argument('-csch', '--catsniffer-channel', type=int, help='Channel for the CatSniffer', default=SNIFFER_DEF_CHANNEL)
    self.parser.add_argument('-jm', '--jammer', type=str, help='Serial path to the Jammer')
    self.parser.add_argument('-jmb', '--jammer-baudrate', type=int, help='Baudrate for the Jammer', default=115200)
    # Flags
    self.parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode like sniffing packets')
    self.args = self.parser.parse_args()
    self.logger = logging.getLogger(SCRIPT_NAME)

    self.catsniffer = Sniffer(logger=logging.getLogger("CatSniffer"))
    self.jammer = Jammer(logger=logging.getLogger("Jammer"))
    self.jammer_configured = False
    self.capture_started = True

  def main(self):
    if not self.args.catsniffer:
        raise UsageError("Please provide the serial path to the CatSniffer")

    if self.args.jammer:
        self.jammer.set_serial_path(self.args.jammer)
        self.jammer.set_serial_baudrate(self.args.jammer_baudrate)
        self.jammer.open()
        self.jammer_configured = True
        self.logger.debug("Jammer initialized")
    
    self.catsniffer.set_serial_path(self.args.catsniffer)
    self.catsniffer.set_channel(self.args.catsniffer_channel)
    self.catsniffer.start_sniffer()
    self.logger.debug("Starting CatBee")
    print("="*20, "CatBee", "="*20)
    print("CatSniffer: ", self.catsniffer.serial_path)
    print("Channel: ", self.catsniffer.channel)
    if self.jammer_configured:
      print("Jammer: ", self.jammer.serial_path)
      print("Baudrate: ", self.jammer.serial_worker.baudrate)
    
    print("="*46)
    
    while self.capture_started:
      packet = self.catsniffer.recv()
      if packet is not None:
        tisniffer_packet = TISnifferPacket(packet)
        if tisniffer_packet.is_command_response():
          continue
        try:
          pkt = Dot15d4(tisniffer_packet.payload)
          if self.args.verbose:
            print(pkt)
          
          # We are only interested in Association Response and Disassociation Request
          # So we can jam the network when the association response is received
          if is_association_response(pkt):
            print("="*20, "Association Response", "="*20)
            print("Destination PAN ID: ", pkt.dest_panid)
            print("Destination Address: ", fmt_addr_to_hex(pkt.dest_addr))
            print("Source Address: ", fmt_addr_to_hex(pkt.src_addr))
            print("Source PAN ID: ", pkt.src_panid)
            if self.jammer.is_connected():
              self.jammer.start_jamming()
              print("Start jamming!")
          
        except Exception as e:
          self.logger.error("Error decoding packet: %s", e)
          self.logger.error("Packet: %s", binascii.hexlify(tisniffer_packet.payload))
  
  
  def stop(self):
    self.capture_started = False
    if self.jammer.is_connected():
      self.jammer.stop_jamming()
      self.jammer.close()
      self.logger.debug("Jammer stopped")
    self.catsniffer.stop_sniffer()
    self.logger.debug("CatBee stopped")

if __name__ == "__main__":
  catbee = CatBee()
  try:
      catbee.main()
  except UsageError as e:
      os._exit(1)
  except KeyboardInterrupt:
      catbee.stop()
      os._exit(0)