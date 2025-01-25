#setting up environment
pip install scapy
pip install python-nmap
pip instal numpy
pip install sklearn

#packet capture
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
  def __init__ (self):
    self.packet_queue = queue.Queue()
    self.stop_capture = threading.Event()
