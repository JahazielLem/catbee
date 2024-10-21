import serial
from .hardware import Board
from .utils import TrivialLogger

JAMMER_DEF_CHANNEL     = 11
JAMMER_CMD_START       = b"S"
JAMMER_CMD_STOP        = b"D"
JAMMER_CMD_SET_CHANNEL = b"C"

class Jammer(Board):
  def __init__(self, channel=JAMMER_DEF_CHANNEL, logger=None):
    super().__init__()
    self.channel = channel
    self.logger = logger if logger else TrivialLogger()
  
  def __str__(self):
    return "Jammer\nPort:{}\nChannel={}\n".format(self.serial_path, self.channel)
  
  def start_jamming(self):
    self.write(JAMMER_CMD_START)
    self.logger.info("Jamming started")
  
  def stop_jamming(self):
    self.write(JAMMER_CMD_STOP)
    self.logger.info("Jamming stopped")

  def set_channel(self, channel):
    self.write(JAMMER_CMD_SET_CHANNEL + bytes([channel]))
    self.logger.info("Channel set to %d", channel)
    self.channel = channel
  