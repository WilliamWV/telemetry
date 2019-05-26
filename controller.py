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

#TODO: add documentation
SWITCH = 0
HOST = 1

CURRENT_DEVICE_ID = 0
BASE_PORT = 50051
FORWARD_TABLE_NAME = 'MyIngress.ipv4_lpm'
FORWARD_MATCH_FIELD = 'hdr.ipv4.dstAddr'
FORWARD_ACTION = 'MyIngress.ipv4_forward'
BITS_PER_SWITCH = 8 # number of bits to identify a host on a switch

class Link:
    def __init__(self, node1, node2):
        self.node1 = node1
        self.node2 = node2

class Node:
    def __init__(self, name, node_type):
        self.type = node_type
        self.name = name
        # name is 'sxx' for a switch or 'hxx' for a host where xx is a number

class Host(Node):
    def __init__(self, name, ipv4):
        global HOST
        Node.__init__(self, name, HOST)
        self.ipv4 = ipv4
    def get_IPv4(self):
        return self.ipv4

class Switch(Node):
    def __init__(self, name, p4info_helper):
        global SWITCH
        Node.__init__(self, name, SWITCH)
        self.p4info_helper = p4info_helper
        self.init_switch()
        
    def install_swtrace_rule(self):

        # installing swtrace rule
        table_entry = self.p4info_helper.buildTableEntry(
            table_name='MyEgress.swtrace',
            default_action=True,
            action_name='MyEgress.add_swtrace',
            action_params={'swid': int(self.name[1:])}
        )
        self.switch.WriteTableEntry(table_entry)


    def get_IPv4(self):
        return '10.0.%02x.0' % (int(self.name[1:])) # IPv4 table match


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

        
    def add_rule(self, rule):
        global FORWARD_ACTION, FORWARD_TABLE_NAME, FORWARD_MATCH_FIELD
        table_entry = self.p4info_helper.buildTableEntry(
            table_name=FORWARD_TABLE_NAME,
            match_fields={FORWARD_MATCH_FIELD: rule['match_field']},
            action_name=FORWARD_ACTION,
            action_params={'dstAddr': rule['dstAddr'], 'port': rule['port']}   
        )
        self.switch.WriteTableEntry(table_entry)

    def get_switch(self):
        return self.switch


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
                'port' : port
            }    
        elif n2.type == HOST:
            return {
                'match_field' : (n2.get_IPv4(), 32), 
                'dstAddr': '00:00:00:00:%02x:%02x' % (n1_num, n2_num),
                'port' : port
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
        

    def adjust_rule(self, rule, sw):
        return {
                'match_field' : (sw.get_IPv4(), 24), 
                'dstAddr': rule['dstAddr'],
                'port' : rule['port']
            }    

    # create entries on tables switches to represent each switch that are not connected with it so that they can route to each other
    def fill_switch_tables(self):
        global SWITCH
        switches = [self.nodes[s] for s in self.nodes if self.nodes[s].type == SWITCH]
        for s1 in range(len(switches) - 1):
            next_hops = self.get_next_hop_for_all_sw(switches[s1].name)
            for s2 in range(s1+1, len(switches)):
                if not self.has_link(switches[s1].name, switches[s2].name):
                    print ("Not found link between " + switches[s1].name + " and " + switches[s2].name)
                    switches[s1].add_rule(self.adjust_rule(next_hops[switches[s2].name], switches[s2]))



def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print


def readTableRulesFromSwitches(p4info_helper, switches):
    for sw in switches:
        readTableRules(p4info_helper, sw)
        print "-----"


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        s1 = Switch('s1', p4info_helper)
        s2 = Switch('s2', p4info_helper)
        s3 = Switch('s3', p4info_helper)

        switches = [s1, s2, s3]


        h1 = Host('h1', '10.0.1.1')
        h11 = Host('h11', '10.0.1.11')
        h2 = Host('h2', '10.0.2.2')
        h22 = Host('h22', '10.0.2.22')
        h3 = Host('h3', '10.0.3.3')

        topo = Topology()
        topo.add_node(s1)
        topo.add_node(s2)
        topo.add_node(s3)
        topo.add_node(h1)
        topo.add_node(h11)
        topo.add_node(h2)
        topo.add_node(h22)
        topo.add_node(h3)
        
        # PHASE 1: INSTALL THE P4 PROGRAM ON THE SWITCHES
        # TODO: transferir essa parte para dentro dos switches  
        print '####################'
        print '# Starting Phase 1 #'
        print '####################'
        s1.get_switch().SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.get_switch().SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"
        s3.get_switch().SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        sw_obj = [s.get_switch() for s in switches]
        readTableRulesFromSwitches(p4info_helper, sw_obj)

        print 'Phase 1 finished, press [ENTER] to continue.'
        raw_input()

        # PHASE 2: INSTALL IPv4 FORWARDING RULES ON THE SWITCHES
        print '####################'
        print '# Starting Phase 2 #'
        print '####################'

        topo.add_link('s1', 'h1', 2)
        topo.add_link('s1', 'h11', 1)
        topo.add_link('s1', 's2', 3)
        topo.add_link('s1', 's3', 4)

        topo.add_link('s2', 'h2', 2)
        topo.add_link('s2', 'h22', 1)
        topo.add_link('s2', 's1', 3)
        topo.add_link('s2', 's3', 4)

        topo.add_link('s3', 'h3', 1)
        topo.add_link('s3', 's1', 2)
        topo.add_link('s3', 's2', 3)

        topo.fill_switch_tables()

        # TODO: realizar isso automaticamente dentro dos switches
        for s in switches:
            s.install_swtrace_rule()

        readTableRulesFromSwitches(p4info_helper, sw_obj)

        print 'Phase 2 finished, press [ENTER] to continue.'
        raw_input()

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
