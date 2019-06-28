#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import json
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

###############################################################################
#######################        CONSTANTS        ###############################
###############################################################################

# Constants to identify the type of an instance of class Node in Topology
SWITCH = 0
HOST = 1

# Incremental counter to identify the device, used to initialize a behavioral 
# model to a switch
CURRENT_DEVICE_ID = 0

# Base port where each switch is connected, the real port is obtained by the 
# sum of this value with
BASE_PORT = 50051

# Constants used when creating forwarding rules
FORWARD_TABLE_NAME = 'MyIngress.ipv4_lpm'
FORWARD_MATCH_FIELD = 'hdr.ipv4.dstAddr'
FORWARD_ACTION = 'MyIngress.ipv4_forward'
BITS_PER_SWITCH = 8 # number of bits to identify a host on a switch

#file constants
RULES_DIR = 'rules'



###############################################################################
### class Node                                                              ###
###  * Used to represent a node on the network topology, eventually it will ###
###    be specialized to either a Host or a Switch.                         ###
###  * Contain basic and general information like the node name represented ###
###    by a string and its type to differ between switch and host.          ###
###  * Structure:                                                           ###
###    - self.type                                                          ###
###    - self.name                                                          ###
###############################################################################
class Node:
    def __init__(self, name, node_type):
        self.type = node_type
        self.name = name
        # name is 'sxx' for a switch or 'hxx' for a host where xx is a number



###############################################################################
### class Host                                                              ###
###  * Represents a host on the topology, beyond the content of its Node,   ###
###    this class also represents the Host IPv4 address                     ###
###  * Structure:                                                           ###
###    - self.type                                                          ###
###    - self.name                                                          ###
###    - self.ipv4                                                          ###
###  * Methods:                                                             ###
###    - __init__(name, ipv4)                                               ###
###    - get_IPv4()                                                         ###
###############################################################################
class Host(Node):
    def __init__(self, name, ipv4):
        global HOST
        Node.__init__(self, name, HOST)
        self.ipv4 = ipv4


    def get_IPv4(self):
        return self.ipv4



###############################################################################
### class Switch                                                            ###
###  * Represents a switch on the topology, this class is used to install   ###
###    rules on the table switch, including rules related to forwarding and ###
###    to telemetry.                                                        ###
###  * Structure:                                                           ###
###    - self.type                                                          ###
###    - self.name                                                          ###
###    - self.p4info_helper // used to build table entries                  ###
###    - self.switch        // represents an object of                      ###
###                         // p4runtime_lib.bmv2.Bmv2SwitchConnection      ###
###    - self.rules         // forwarding rules of the switch               ###
###  * Methods:                                                             ###
###    - __init__ (name, p4info_helper, bmv2_file_path)                     ###
###    - install_telemetry_rule()                                           ###
###    - get_IPv4 ()                                                        ###
###    - init_switch ()             // self.switch object                   ###
###    - add_rule(rule)             // forwarding rule                      ###
###    - get_switch()               // self.switch                          ###
###    - write_rule_on_file(rule)   // writes a rule on a file so that it   ###
###                                 // can be readed by the statistical     ###
###                                 // controller                           ###
###    - clear_rule_file()                                                  ###
###############################################################################
class Switch(Node):
    def __init__(self, name, p4info_helper, bmv2_file_path):
        global SWITCH
        Node.__init__(self, name, SWITCH)
        self.rules = []
        self.p4info_helper = p4info_helper
        self.init_switch()
        self.switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        self.install_telemetry_rule()
        self.clear_rule_file()
        

    def install_telemetry_rule(self):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name='MyEgress.swtrace',
            default_action=True,
            action_name='MyEgress.add_swtrace',
            action_params={'swid': int(self.name[1:])}
        )
        self.switch.WriteTableEntry(table_entry)

    
    def clear_rule_file(self):
        global RULES_DIR
        file_name = RULES_DIR + self.name
        file = open(file_name, 'w')
        file.close()

    def get_IPv4(self):
        return '10.0.%d.0' % (int(self.name[1:])) # IPv4 table match


    def init_switch(self):
        global CURRENT_DEVICE_ID, BASE_PORT
        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=self.name,
            address='127.0.0.1:'+str(BASE_PORT + CURRENT_DEVICE_ID),
            device_id=CURRENT_DEVICE_ID,
            proto_dump_file='logs/'+str(self.name)+'-p4runtime-requests.txt')
        CURRENT_DEVICE_ID += 1
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        self.switch.MasterArbitrationUpdate()

    
    
    # A rule is a dictionary defined as:
    # rule {
    #   'dstAddr'     : mac address to forward
    #   'port'        : port to froward
    #   'match_field' : tuple of (ipv4 to match, size to match)
    #   'last_hop'    : boolean that identify if this is a last hop action
    #   'id'          : identifier of the rule to statistical use
    #}
    def add_rule(self, rule):
        global FORWARD_ACTION, FORWARD_TABLE_NAME, FORWARD_MATCH_FIELD
        #self.print_rule(rule)
        rule['id'] = len(self.rules)
        self.rules.append(rule)

        table_entry = self.p4info_helper.buildTableEntry(
            table_name=FORWARD_TABLE_NAME,
            match_fields={FORWARD_MATCH_FIELD: rule['match_field']},
            action_name=FORWARD_ACTION,
            action_params={'dstAddr': rule['dstAddr'], 'port': rule['port'], 'ruleId': rule['id'], 'lastHop': int(rule['last_hop'])}   
        )
        
        self.write_rule_on_file(rule)
        self.switch.WriteTableEntry(table_entry)
    
    def write_rule_on_file(self, rule):
        global RULES_DIR
        file_name = RULES_DIR+self.name
        file = open(file_name, 'a')
        file.write(str(rule) + '\n')
        file.close()


    def print_rule(self, rule):
        global FORWARD_ACTION, FORWARD_TABLE_NAME, FORWARD_MATCH_FIELD
        print "Table name: " + FORWARD_TABLE_NAME
        print "Match Address: " + rule['match_field'][0] + ' \\' + str(rule['match_field'][1])
        print "Action: " + FORWARD_ACTION
        print "Last hop: " + str(rule['last_hop'])
        print "Destination MAC: " + rule['dstAddr']
        print "Destination port: " + str(rule['port'])
        print "\n"


    def get_switch(self):
        return self.switch



###############################################################################
### class Topology                                                          ###
###  * Represents a global view of the network topology.                    ###
###  * Used to add nodes and links to the network, create rules to be       ###
###    installed on switch tables and determine the next hop between        ###
###    distant switches to reduce the number of hops.                       ###
###  * Structure:                                                           ###
###    - self.nodes         // dictionary {node_name -> node}               ###
###    - self.links         // list of tuples (src, dst, fw_rule)           ###
###  * Methods:                                                             ###
###    - __init__ (file, p4info_helper, bmv2_file_path)                     ###
###    - add_node (node)                                                    ###
###    - make_rule (n1, n2, port)                                           ###
###    - has_link (node1, node2)                                            ###
###    - add_link(node1, node2, port)                                       ###
###    - get_next_hop_for_all_sw(sw)                                        ###
###    - adjust_rule(rule, sw)                                              ###
###    - fill_switch_tables()                                               ###
###    - build_host_ip(host)                                                ###
###    - build_topo(file, p4info_helper, bmv2_file_path)                    ###
###############################################################################
class Topology:
    # represents topology nodes

    def __init__(self, file, p4info_helper, bmv2_file_path):
        self.nodes = {}
        self.links = []
        self.build_topo(open(file), p4info_helper, bmv2_file_path)

    def build_host_ip(self, host):
        return '10.0.%d.%d' % (int(host[1:(len(host)-1)]) , int(host[1:]))

    # Construction of the topology
    def build_topo(self, file, p4info_helper, bmv2_file_path):
        js = json.load(file)
        
        sw = [str(s) for s in js["switches"]]

        sw_links = {}
        sw.sort()
        for s in sw:
            self.add_node(Switch(s, p4info_helper, bmv2_file_path))
            sw_links[s] = []

        ht = [str(h) for h in js["hosts"]]
        for h in ht:
            self.add_node(Host(h, self.build_host_ip(h)))

        lk = [[str(l[0]), str(l[1])] for l in js["links"]]

        for (e1, e2) in lk:
            if e1[0] == 's':
                sw_links[e1].append(e2)
            if e2[0] == 's':
                sw_links[e2].append(e1)

        for sl in sw_links:
            sw_links[sl].sort()
            port = 1
            for n in sw_links[sl]:
                self.add_link(sl, n, port)
                port += 1


        file.close()
        self.fill_switch_tables()


    def add_node(self, node):
        self.nodes[node.name] = node

    
    def make_rule(self, n1, n2, port):
        global SWITCH, HOST
        n1_num = int(n1.name[1:])
        n2_num = int(n2.name[1:])

        if n2.type == SWITCH:
            return {
                'match_field' : (n2.get_IPv4(), 24), 
                'dstAddr': '00:00:00:%02x:%02x:00' % (n2_num, n2_num),
                'port' : port,
                'last_hop' : False
            }    
        elif n2.type == HOST:
            return {
                'match_field' : (n2.get_IPv4(), 32), 
                'dstAddr': '00:00:00:00:%02x:%02x' % (n1_num, n2_num),
                'port' : port,
                'last_hop' : True
            }

    def has_link(self, node1, node2):
        for link in self.links:
            if (link[0] == node1 and link[1] == node2):
                return True
        return False


    def add_link(self, node1, node2, port):
        global SWITCH, HOST

        if node1 not in self.nodes or node2 not in self.nodes:
            raise Exception("Both nodes must be added to the topology before adding links to them")
        n1 = self.nodes[node1]
        n2 = self.nodes[node2]

        if n1.type == HOST and n2.type == HOST:
            raise Exception("A host must not be connected to another host, attempted with host " + node1 + " and " + node2)
        
        if n1.type == SWITCH:
            rule = self.make_rule(n1, n2, port)
            n1.add_rule(rule)
            self.links.append((node1, node2, rule))
        
    #returns a dictionary associating each switch to the rule that represents the next hop
    #from the argument sw to this switch 
    def get_next_hop_for_all_sw (self, sw):
        global SWITCH
        answer = {}
        switches = [s for s in self.nodes if self.nodes[s].type == SWITCH and s != sw]
        
        next_hop =  {s : None for s in switches} # will contains the next hop for all switches
        
        queue = [sw]
        
        while len(queue) > 0:
            current = queue[0]
            queue = queue[1:]

            current_links = [l for l in self.links if l[0] == current]
            for link in current_links:
                other_sw = link[1] 
                if other_sw != sw and self.nodes[other_sw].type == SWITCH and next_hop[other_sw] == None:
                    if current == sw:
                        next_hop[other_sw] = link[2]
                    else:
                        next_hop[other_sw] = next_hop[current]
                    queue.append(other_sw)

        return next_hop
        
    # Modify an existing rule changing the match fields to map for other switch to the same
    # forwarding address and port
    def adjust_rule(self, rule, sw):
        return {
                'match_field' : (sw.get_IPv4(), 24), 
                'dstAddr': rule['dstAddr'],
                'port' : rule['port'],
                'last_hop' : False
            }    

    # create entries on tables switches to represent each switch that are not connected with it so that they can route to each other
    def fill_switch_tables(self):
        global SWITCH
        switches = [self.nodes[s] for s in self.nodes if self.nodes[s].type == SWITCH]
        for s1 in range(len(switches)):
            next_hops = self.get_next_hop_for_all_sw(switches[s1].name)
            for s2 in range(len(switches)):
                if s1!=s2 and not self.has_link(switches[s1].name, switches[s2].name):
                    switches[s1].add_rule(self.adjust_rule(next_hops[switches[s2].name], switches[s2]))



###############################################################################
#####################          GENERAL FUNCTIONS          #####################
###############################################################################  




def main(p4info_file_path, bmv2_file_path):
    global RULES_DIR
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        print '####################################'
        print '# Controller for In-Band Telemetry #'
        print '####################################'

        try:
            os.mkdir(RULES_DIR)
        except OSError, WindowsError:
            pass


        RULES_DIR = RULES_DIR + '/'
        
        
        topo = Topology('topology.json', p4info_helper, bmv2_file_path)
        
        
        ## THE END
        print 'THE END.'
    except KeyboardInterrupt:
        print " Shutting down."

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
