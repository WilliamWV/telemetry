#!/usr/bin/env python
import sys
import struct
import time
import ast
import argparse

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


# if a flow dows not generate a packet in the following time (in seconds) it will be set to desactive
ACTIVE_THRESHOLD = 2 
# time interval where one verification of active flows will be executed
VERIFY_TIME = 1
# directory where the rules installed on switches are saved
RULES_DIR = 'rules'
# minimum time between two congestion reports from the same switch in seconds
CONGESTION_TIME = 1 
# thresholds from which a switch will be considered congested
DELAY_THRESHOLD = 0 # us
QUEUE_THRESHOLD = 0 # packets on queue

# used while reading packets` traces
PRIMITIVE_TYPES = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))

#type used to identify mri on ethernet
MRI_TYPE = 0x6041

###############################################################################
### class Rule                                                              ###
###  * Represents a rule on the forwarding table of one switch              ###
###  * Used to store rule information and to keep track of how many times   ###
###    this rule is used.                                                   ###
###  * Structure:                                                           ###
###    - self.id            // identifies the rule on the traces and on the ###
###                         // file containing this rules                   ###
###    - self.key_addr      // destination address to match this rule       ###
###    - self.prefix_size   // prefix_size of the address to match          ###
###    - self.egress_port                                                   ###
###    - self.times_used                                                    ###
###  * Methods:                                                             ###
###    - __init__ (id, key, pr_size, port)                                  ###
###    - increment_uses()                                                   ###
###############################################################################

class Rule:

  def __init__(self, id, key, pr_size, port):
    
    self.id = id
    self.key_addr = key
    self.prefix_size = pr_size
    self.egress_port = port
    self.times_used = 0

  def increment_uses(self):
    self.times_used += 1

###############################################################################
### class Flow                                                              ###
###  * Represents a flow passing through the switch, a flow here is         ###
###    identified by its source address and is used to store info like the  ###
###    time where the flow begins and if the flow is active or not, this is ###
###    used to determine which flows are competing on the switch            ###
###  * Also used to keep track of how many packets this flow generated      ###
###  * Structure:                                                           ###
###    - self.src           // source host of the flow                      ###
###    - self.init_time                                                     ###
###    - self.num_of_pkts                                                   ###
###    - self.last_use                                                      ###
###    - self.active                                                        ###
###  * Methods:                                                             ###
###    - __init__ (init_time, src)                                          ###
###    - increment_pkts()                                                   ###
###    - verify_active()             // checks if this flow is active by    ###
###                                  // comparing the last use time with a  ###
###                                  // threshold                           ###
###############################################################################

class Flow:

  def __init__(self, init, src):
    self.src = src
    self.init_time = init
    self.num_of_pkts = 0
    self.last_use = -1
    self.active = False

  def increment_pkts(self):
    self.num_of_pkts += 1
    self.last_use = time.time()
    self.active = True

  def verify_active(self):
    if (time.time() - self.last_use > ACTIVE_THRESHOLD):
      self.active = False


###############################################################################
### class Switch                                                            ###
###  * Represents a switch of the network containing information of the     ###
###    flows and rules of this switch, also keeping track of the average    ###
###    delay and the average queue ocupacy of this switch                   ###
###  * This class is also responsible for printing the congestion reports   ###
###  * Structure:                                                           ###
###    - self.name                                                          ###
###    - self.last_delay                                                    ###
###    - self.last_queue_ocupacy                                            ###
###    - self.pkts                                                          ###
###    - self.flows                                                         ###
###    - self.rules                                                         ###
###    - self.last_congestion_print   // used to implement a time interval  ###
###                                   // between congestion reports         ###
###  * Methods:                                                             ###
###    - __init__ (name)                                                    ###
###    - init_rules()              // reads the switch rules from file      ###
###    - add_flow(flow)                                                     ###
###    - income_pkt(src, trace)    // used to update trace information      ###
###                                // based on a newly received packet      ###
###    - verify_flows()            // used to verify which flows remain     ###
###                                // active                                ###
###    - print_congestion()                                                 ###
###############################################################################
class Switch:

  def __init__(self, name):
    self.name = name
    self.delay = 0
    self.queue_ocupacy = 0
    self.pkts = 0
    self.flows = {} # {flow source -> Flow class instance}
    self.rules = {} # {rule id     -> Rule class instance}
    self.last_congestion_print = -1
    self.init_rules()
    self.alpha = 0.1 # used to estimate the current delay and the current queue
                     # occupation. 

  def init_rules(self):
    global RULES_DIR
    rules_file = open(RULES_DIR + '/' + self.name)
    for line in rules_file.readlines():
      r = ast.literal_eval(line)
      rule = Rule(r['id'], r['match_field'][0], r['match_field'][1], r['port'])
      self.rules[r['id']] = rule
  
  def add_flow(self, flow):
    self.flows[flow.src] = flow

  
  def income_pkt (self, src, trace):
    global QUEUE_THRESHOLD, DELAY_THRESHOLD, CONGESTION_TIME
    try:
      flow = self.flows[src]
      flow.increment_pkts()
    except KeyError:
      new_flow = Flow(time.time(), src)
      new_flow.increment_pkts()
      self.add_flow(new_flow)

    rule = self.rules[trace.rule_id]
    rule.increment_uses()
    if (trace.qdepth > QUEUE_THRESHOLD or trace.timedelta > DELAY_THRESHOLD) and time.time() - self.last_congestion_print > CONGESTION_TIME:
      self.print_congestion()
      self.last_congestion_print = time.time()

    self.delay = (1-self.alpha) * self.delay + self.alpha * trace.timedelta  
    self.queue_ocupacy =  (1-self.alpha) * self.queue_ocupacy + self.alpha * trace.qdepth
    
  def verify_flows(self):
    active_flows = [f for f in self.flows.values() if f.active]
    for f in active_flows:
      f.verify_active()

  
  def print_congestion(self):
    print '========================  CONGESTION REPORT  ========================'
    print 'Congestion on switch ' + str(self.name) + ' caused by the following flows'
    active_flows = [f for f in self.flows.values() if f.active]
    for f in active_flows:
      print '\tFlow from ' + str(f.src) + ' started ' + '%.2f' % (time.time() - f.init_time) + ' seconds ago -> ' + str(f.num_of_pkts) + ' packets'
    print 'Delay estimation %.2f' % (float(self.delay)/1000.0) + 'ms'
    print 'Queue ocupacy estimation: %.0f' % (self.queue_ocupacy) + ' packets'
    print 'The forwarding rules of this switch are:'
    for rule in self.rules.values():
      print '\tRule ' + str(rule.id) + ') ' + str(rule.key_addr) + '/' + str(rule.prefix_size) + ' => port ' + str(rule.egress_port) + ' (used ' + str(rule.times_used) + ' times)'




ETHERNET_SIZE = 14
SWTRACE_SIZE = 16
MRI_SIZE = 4
IPV4_SIZE_BEFORE_SRC = 12

def bytes_to_number(pkt, init, size):
    num = 0
    for i in range(size):
      num = num * 256 + pkt[init + i]
    return num


def num_of_traces(pkt):
  return bytes_to_number(pkt, ETHERNET_SIZE, 2)

def get_source(pkt):
    
    init_byte = ipv4_start_byte(pkt) + IPV4_SIZE_BEFORE_SRC
    source = ''
    for i in range(4):
      source += str(pkt[init_byte + i])
      if i < 3:
        source+='.'
    return source
 
def ipv4_start_byte(pkt):
  return ETHERNET_SIZE + MRI_SIZE + SWTRACE_SIZE * bytes_to_number(pkt, ETHERNET_SIZE + 2, 2)


class Trace:
  
  def __init__(self, pkt, i):
    global ETHERNET_SIZE, SWTRACE_SIZE, MRI_SIZE
    self.swid = bytes_to_number(pkt, ETHERNET_SIZE + MRI_SIZE + i*SWTRACE_SIZE, 2)
    self.qdepth = bytes_to_number(pkt, ETHERNET_SIZE + MRI_SIZE + i*SWTRACE_SIZE + 2, 4)
    self.timestamp = bytes_to_number(pkt, ETHERNET_SIZE + MRI_SIZE + i*SWTRACE_SIZE + 6, 4)
    self.timedelta = bytes_to_number(pkt, ETHERNET_SIZE + MRI_SIZE + i*SWTRACE_SIZE + 10, 4)
    self.rule_id = bytes_to_number(pkt, ETHERNET_SIZE + MRI_SIZE + i*SWTRACE_SIZE + 14, 2)
    
  
prev_time = time.time()
switchs = {} # switch id -> Switch class instance

def is_mri_pkt(pkt):
  ether_type = bytes_to_number(pkt, 12, 2)
  return ether_type == MRI_TYPE

def handle_pkt(pkt):
    global prev_time
    pkt_bytes = [ord(b) for b in str(pkt)]
    if is_mri_pkt(pkt_bytes):

      src = get_source(pkt_bytes)
      
      swtraces = [Trace(pkt_bytes, i) for i in range(num_of_traces(pkt_bytes))]
      
      if(time.time() - prev_time > VERIFY_TIME):
        for sw in switchs.values():
          sw.verify_flows()
        prev_time = time.time()

      for trace in swtraces:
        try:
          switchs[trace.swid].income_pkt(src, trace) 
        except KeyError:
          switchs[trace.swid] = Switch('s%02d' % (trace.swid))
          switchs[trace.swid].income_pkt(src, trace)

    
    sys.stdout.flush()


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    iface = 'h070-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Statisticl analiser')
    parser.add_argument('-d', '--delay', help='Delay threshold in milisseconds',
                        type=int, action="store", required=True)
    parser.add_argument('-q', '--queue_oc', help='Queue ocupacy threshold in packets', 
                        type=int, action="store", required=True)
    args = parser.parse_args()

    DELAY_THRESHOLD = args.delay * 1000
    QUEUE_THRESHOLD = args.queue_oc

    main()

