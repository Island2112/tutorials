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
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2


def setupMirrorSession(p4info_helper, switch, session_id, egress_port):
    mirror_session = p4info_helper.buildMirrorSessionEntry(session_id, egress_port)
    switch.WriteMirrorSession(mirror_session, dry_run=False)


def writeForwardingRule(p4info_helper, switch, dst_ip_addr, dst_eth_addr, egress_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": egress_port
        })
    switch.WriteTableEntry(table_entry)
    print "Installed forwarding rule on %s" % switch.name

def writeFilteringRule(p4info_helper, switch, protocol, port, direction):

    action_name = "MyEgress.action_clone_e2e"
    table_name  = "MyEgress.table_" + protocol + "_" + direction + "Port_exact"
    match_field = "hdr." + protocol + "." + direction + "Port"
    table_entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields={ match_field: port },
        action_name=action_name)
    switch.WriteTableEntry(table_entry)
    print "Installed filtering rule on %s" % switch.name

def writeFilteringRules(p4info_helper, switch, protocol, port):
 
    writeFilteringRule(p4info_helper, switch, protocol, port, "src")
    writeFilteringRule(p4info_helper, switch, protocol, port, "dst")

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
            # DONE For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names            
            table_name = p4info_helper.get_tables_name(entry.table_id)
            action_name = p4info_helper.get_actions_name(entry.action.action.action_id)
            result = entry.__repr__()
            result = result.replace(entry.table_id.__repr__(), table_name)
            result = result.replace(entry.action.action.action_id.__repr__(), action_name)

            print result
            print '-----'

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create switch connection objects for s1, s2, and s3;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"

        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        # Switch port mapping:
        # s1:  1:h1   2:s2    3:s3    
        # s2:  1:h2   2:s1    3:s3    
        # s3:  1:h3   2:s1    3:s2    

        writeForwardingRule(p4info_helper, switch=s1, dst_ip_addr="10.0.1.1", dst_eth_addr="00:00:00:00:01:01", egress_port=1)
        writeForwardingRule(p4info_helper, switch=s1, dst_ip_addr="10.0.2.2", dst_eth_addr="00:00:00:00:02:02", egress_port=2)

        writeForwardingRule(p4info_helper, switch=s2, dst_ip_addr="10.0.1.1", dst_eth_addr="00:00:00:00:01:01", egress_port=2)
        writeForwardingRule(p4info_helper, switch=s2, dst_ip_addr="10.0.2.2", dst_eth_addr="00:00:00:00:02:02", egress_port=1)

        writeFilteringRules(p4info_helper, switch=s1, protocol="tcp", port=1234)

        setupMirrorSession(p4info_helper, switch=s1, session_id=1, egress_port=3)

        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)

 
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/p4dpi.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/p4dpi.json')
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
