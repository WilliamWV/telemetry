#!/usr/bin/env python
import sys
import struct
import time
import ast

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
QUEUE_THRESHOLD = 30 # packets on queue

# used while reading packets` traces
PRIMITIVE_TYPES = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))

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
###    - self.avg_delay                                                     ###
###    - self.avg_queue_ocupacy                                             ###
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
    self.avg_delay = 0
    self.avg_queue_ocupacy = 0
    self.pkts = 0
    self.flows = {} # {flow source -> Flow class instance}
    self.rules = {} # {rule id     -> Rule class instance}
    self.last_congestion_print = -1
    self.init_rules()

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

    rule = self.rules[trace['rule_id']]
    rule.increment_uses()
    if (trace['qdepth'] > QUEUE_THRESHOLD or trace['timedelta'] > DELAY_THRESHOLD) and time.time() - self.last_congestion_print > CONGESTION_TIME:
      self.print_congestion()
      self.last_congestion_print = time.time()

    self.avg_delay = ((self.avg_delay * self.pkts) + trace['timedelta']) / (self.pkts + 1)  
    self.avg_queue_ocupacy = ((self.avg_queue_ocupacy * self.pkts) + trace['qdepth']) / (self.pkts + 1)
    self.pkts += 1
  
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
    print 'This congestion is causing an average delay of ' + str(float(self.avg_delay)/1000.0) + 'ms'
    print 'The queue ocupacy of this switch is ' + str(self.avg_queue_ocupacy) + '%'
    print 'The forwarding rules of this switch are:'
    for rule in self.rules.values():
      print '\tRule ' + str(rule.id) + ') ' + str(rule.key_addr) + '/' + str(rule.prefix_size) + ' => port ' + str(rule.egress_port) + ' (used ' + str(rule.times_used) + ' times)'


###############################################################################
### class Traces                                                            ###
###  * Represent all the traces carried by a packet, this class is used to  ###
###    store a list of these traces, also store the source host address     ###
###  * Build the traces from a scapy packet                                 ###
###  * Structure:                                                           ###
###    - self.traces                                                        ###
###    - self.src                                                           ###
###  * Methods:                                                             ###
###    - __init__ (pkt)                                                     ###
###    - trace_to_dict(layer)      // based on a layer of the scapy packet  ###
###                                // that contains a switch trace builds a ###
###                                // python dictionary associating fields  ###
###                                // with its values                       ###
###    - build_traces(pkt)         // iterate through the packet layers     ###
###                                // looking for traces                    ###
###############################################################################
class Traces:
  
  def __init__(self, pkt):
    self.traces = []
    self.src = pkt[IP].src
    self.build_traces(pkt)

 
  def trace_to_dict (self, layer):
    global PRIMITIVE_TYPES
    d = {}

    if not getattr(layer, 'fields_desc', None):
      return
    for f in layer.fields_desc:
      value = getattr(layer, f.name)
      if value is type(None):
        value = None
      if not isinstance(value, PRIMITIVE_TYPES):
        value = self.trace_to_dict(value)
      d[f.name] = value
    return d


  def build_traces(self, pkt):
    depth = 0
    while True:
      layer = pkt.getlayer(depth)
      if not layer:
        break
      if layer.name == 'SwitchTrace':
        self.traces.append(self.trace_to_dict(layer))
      
      depth+=1


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

class SwitchTrace(Packet):
    fields_desc = [
                  ShortField("swid", 0),
                  IntField("qdepth", 0),
                  IntField("timestamp", 0),
                  IntField("timedelta", 0),
                  ShortField("rule_id", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

prev_time = time.time()
switchs = {} # switch id -> Switch class instance




def handle_pkt(pkt):
    global prev_time
    
    swtraces = Traces(pkt)
    
    if(time.time() - prev_time > VERIFY_TIME):
      for sw in switchs.values():
        sw.verify_flows()
      prev_time = time.time()

    for trace in swtraces.traces:
      sw = trace['swid']
      try:

        switchs[sw].income_pkt(swtraces.src, trace) 
      except KeyError:
        switchs[sw] = Switch('s' + str(sw))
        switchs[sw].income_pkt(swtraces.src, trace)

    pkt.show2()
    #hexdump(pkt)
    sys.stdout.flush()


def main():
    iface = 'h99-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
