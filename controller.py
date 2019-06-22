#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
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
###    - install_clone_rule()                                               ###
###    - clear_rule_file()                                                  ###
###############################################################################
class Switch(Node):
    def __init__(self, name, p4info_helper, bmv2_file_path):
        global SWITCH
        Node.__init__(self, name, SWITCH)
        self.rules = []
        self.p4info_helper = p4info_helper
        self.clone_session = int(self.name[1:])
        self.init_switch()
        self.switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        self.install_telemetry_rule()
        self.install_clone_rule()
        self.clear_rule_file()
        

    def install_telemetry_rule(self):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name='MyEgress.swtrace',
            default_action=True,
            action_name='MyEgress.add_swtrace',
            action_params={'swid': int(self.name[1:])}
        )
        self.switch.WriteTableEntry(table_entry)

    def install_clone_rule (self):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name='MyEgress.clone_session',
            default_action=True,
            action_name='MyEgress.do_clone',
            action_params={'session_id': self.clone_session}
        )
        self.switch.WriteTableEntry(table_entry)

        print "\nSwitch " + str(self.name) + " using clone session: " + str(self.clone_session)

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
        print "Installing forward rule on switch " + self.name
        self.print_rule(rule)
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
###    - __init__ ()                                                        ###
###    - add_node (node)                                                    ###
###    - make_rule (n1, n2, port)                                           ###
###    - has_link (node1, node2)                                            ###
###    - add_link(node1, node2, port)                                       ###
###    - get_next_hop_for_all_sw(sw)                                        ###
###    - adjust_rule(rule, sw)                                              ###
###    - fill_switch_tables()                                               ###
###############################################################################
class Topology:
    # represents topology nodes

    def __init__(self):
        self.nodes = {}
        self.links = []

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
                    print ("Not found link between " + switches[s1].name + " and " + switches[s2].name)
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
        s01 = Switch('s01', p4info_helper, bmv2_file_path)
        s02 = Switch('s02', p4info_helper, bmv2_file_path)
        s03 = Switch('s03', p4info_helper, bmv2_file_path)
        s04 = Switch('s04', p4info_helper, bmv2_file_path)
        s05 = Switch('s05', p4info_helper, bmv2_file_path)
        s06 = Switch('s06', p4info_helper, bmv2_file_path)
        s07 = Switch('s07', p4info_helper, bmv2_file_path)
        s08 = Switch('s08', p4info_helper, bmv2_file_path)
        s09 = Switch('s09', p4info_helper, bmv2_file_path)
        s10 = Switch('s10', p4info_helper, bmv2_file_path)
        s11 = Switch('s11', p4info_helper, bmv2_file_path)
        s12 = Switch('s12', p4info_helper, bmv2_file_path)
        s13 = Switch('s13', p4info_helper, bmv2_file_path)


        switches = [s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13]


        h011 = Host('h011', '10.0.1.11')
        h012 = Host('h012', '10.0.1.12')
        h013 = Host('h013', '10.0.1.13')
        h021 = Host('h021', '10.0.2.21')
        h022 = Host('h022', '10.0.2.22')
        h031 = Host('h031', '10.0.3.31')
        h041 = Host('h041', '10.0.4.41')
        h042 = Host('h042', '10.0.4.42')
        h061 = Host('h061', '10.0.6.61')
        h070 = Host('h070', '10.0.7.70')
        h071 = Host('h071', '10.0.7.71')
        h081 = Host('h081', '10.0.8.81')
        h082 = Host('h082', '10.0.8.82')
        h083 = Host('h083', '10.0.8.83')
        h084 = Host('h084', '10.0.8.84')
        h085 = Host('h085', '10.0.8.85')
        h086 = Host('h086', '10.0.8.86')
        h111 = Host('h111', '10.0.11.111')
        h112 = Host('h112', '10.0.11.112')
        h121 = Host('h121', '10.0.12.121')
        h122 = Host('h122', '10.0.12.122')
        h123 = Host('h123', '10.0.12.123')
        h131 = Host('h131', '10.0.13.131')
        
        topo = Topology()
        topo.add_node(s01)
        topo.add_node(s02)
        topo.add_node(s03)
        topo.add_node(s04)
        topo.add_node(s05)
        topo.add_node(s06)
        topo.add_node(s07)
        topo.add_node(s08)
        topo.add_node(s09)
        topo.add_node(s10)
        topo.add_node(s11)
        topo.add_node(s12)
        topo.add_node(s13)
        
        topo.add_node(h011)
        topo.add_node(h012)
        topo.add_node(h013)
        topo.add_node(h021)
        topo.add_node(h022)
        topo.add_node(h031)
        topo.add_node(h041)
        topo.add_node(h042)
        topo.add_node(h061)
        topo.add_node(h070)
        topo.add_node(h071)
        topo.add_node(h081)
        topo.add_node(h082)
        topo.add_node(h083)
        topo.add_node(h084)
        topo.add_node(h085)
        topo.add_node(h086)
        topo.add_node(h111)
        topo.add_node(h112)
        topo.add_node(h121)
        topo.add_node(h122)
        topo.add_node(h123)
        topo.add_node(h131)
        

        # PHASE 2: INSTALL IPv4 FORWARDING RULES ON THE SWITCHES
        
        topo.add_link('s01', 'h011', 1)
        topo.add_link('s01', 'h012', 2)
        topo.add_link('s01', 'h013', 3)
        topo.add_link('s01', 's02', 4)
        topo.add_link('s01', 's03', 5)

        topo.add_link('s02', 'h021', 1)
        topo.add_link('s02', 'h022', 2)
        topo.add_link('s02', 's01', 3)
        topo.add_link('s02', 's03', 4)
        
        topo.add_link('s03', 'h031', 1)
        topo.add_link('s03', 's01', 2)
        topo.add_link('s03', 's02', 3)
        topo.add_link('s03', 's04', 4)
        
        topo.add_link('s04', 'h041', 1)
        topo.add_link('s04', 'h042', 2)
        topo.add_link('s04', 's05', 3)
        
        topo.add_link('s05', 's03', 1)
        topo.add_link('s05', 's04', 2)
        topo.add_link('s05', 's06', 3)
        topo.add_link('s05', 's07', 4)
        
        topo.add_link('s06', 'h061', 1)
        topo.add_link('s06', 's05', 2)
        topo.add_link('s06', 's08', 3)
        
        topo.add_link('s07', 'h070', 1)
        topo.add_link('s07', 'h071', 2)
        topo.add_link('s07', 's05', 3)
        topo.add_link('s07', 's09', 4)
        
        topo.add_link('s08', 'h081', 1)
        topo.add_link('s08', 'h082', 2)
        topo.add_link('s08', 'h083', 3)
        topo.add_link('s08', 'h084', 4)
        topo.add_link('s08', 'h085', 5)
        topo.add_link('s08', 'h086', 6)
        topo.add_link('s08', 's06', 7)
        topo.add_link('s08', 's09', 8)
        
        topo.add_link('s09', 's07', 1)
        topo.add_link('s09', 's08', 2)
        topo.add_link('s09', 's10', 3)
        topo.add_link('s09', 's11', 4)
        
        topo.add_link('s10', 's09', 1)
        topo.add_link('s10', 's12', 2)
        topo.add_link('s10', 's13', 3)
        
        topo.add_link('s11', 'h111', 1)
        topo.add_link('s11', 'h112', 2)
        topo.add_link('s11', 's09', 3)
        topo.add_link('s11', 's13', 4)
        
        topo.add_link('s12', 'h121', 1)
        topo.add_link('s12', 'h122', 2)
        topo.add_link('s12', 'h123', 3)
        topo.add_link('s12', 's10', 4)
        
        topo.add_link('s13', 'h131', 1)
        topo.add_link('s13', 's10', 2)
        topo.add_link('s13', 's11', 3)
        

        topo.fill_switch_tables()

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
