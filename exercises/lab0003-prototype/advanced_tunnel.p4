/*

Credits: 

Header definitions for ICMP, TCP, and UDP were inspired by:
https://github.com/p4lang/papers/blob/master/sosr15/DC.p4/includes/headers.p4

Egress table_clone_e2e and action_clone_e2e were inspired by:
Table loosely based on http://csie.nqu.edu.tw/smallko/sdn/p4-clone.htm 

*/

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x0800;
const bit<16> TYPE_IPV6  = 0x86DD;

const bit<8> TYPE_ICMP   = 0x01;
const bit<8> TYPE_ICMPV6 = 0x3A;
const bit<8> TYPE_TCP    = 0x06;
const bit<8> TYPE_UDP    = 0x11;

const bit<32> MIRROR_SESSION = 0x1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLength;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header icmp_t {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdrChecksum;
}

header icmpv6_t {
    bit<8>    type_;
    bit<8>    code;
    bit<16>   hdrChecksum;
}

header tcp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<32>   seqNo;
    bit<32>   ackNo;
    bit<4>    dataOffset;
    bit<4>    res;
    bit<8>    flags;
    bit<16>   window;
    bit<16>   checksum;
    bit<16>   urgentPtr;
}

header udp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   length_;
    bit<16>   checksum;
}

struct metadata {

}

struct headers  {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    icmp_t      icmp;
    icmpv6_t    icmpv6;
    tcp_t       tcp;
    udp_t       udp;  
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    // Layer 2
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4:     parse_ipv4;
            TYPE_IPV6:     parse_ipv6;            
            default:       accept;
        }
    }

    // Layer 3
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            TYPE_TCP:  parse_tcp;
            TYPE_UDP:  parse_udp;
            default:   accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
            TYPE_ICMPV6: parse_icmpv6; 
            TYPE_TCP:    parse_tcp;
            TYPE_UDP:    parse_udp;
            default:     accept;
        }
    }    

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
    }

    // Layer 4 
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   

     apply {
           verify_checksum(
           hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }

}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

     action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table blockedPorts_exact {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        
        blockedPorts_exact.apply();

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (hdr.ipv6.isValid()) {
 
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
 
    

    action action_clone_e2e() {
        clone(CloneType.E2E, MIRROR_SESSION);
    }

    table table_clone_e2e {
        actions = {
            action_clone_e2e;
        }
        size = 1;
        default_action = action_clone_e2e();
    }

    apply {

        if (standard_metadata.instance_type == 0) {
            table_clone_e2e.apply();
        }

    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
