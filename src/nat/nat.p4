/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8>  TYPE_TCP = 0x06;
const bit<32> PUB_IP=0x8c710001;
const bit<32> max_port_num=65535;
const bit<32> h1_IP=0x0a000101;
const bit<32> h2_IP=0x0a000102;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  ctl_flag;
    bit<16> window_size;
    bit<16> checksum;
    bit<16> urgent_num;
}

header Tcp_option_padding_h {
    varbit<160> padding;
}


struct metadata {
    bit<16> tcp_length;
    bit<16> tot_length;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    Tcp_option_padding_h tcp_options_padding;
}
error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        transition consume_remaining_tcp_hdr_and_accept;
    }

    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
}
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

     state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            //TYPE_UDP  : parse_udp;
            TYPE_TCP  : parse_tcp;
            default   : accept;
        }
    }
    state parse_tcp{
        packet.extract(hdr.tcp);
        meta.tcp_length = (bit<16>)hdr.tcp.data_offset * 4;
        meta.tot_length = hdr.ipv4.totalLen-20;
        Tcp_option_parser.apply(packet, hdr.tcp.data_offset,
                                hdr.tcp_options_padding);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<32>> (max_port_num) NAT_IP_table; //record the mapping private hostIP and public port 
    register<bit<16>> (max_port_num) NAT_Port_table; //record the mapping private hostPort and public port
    register<bit<32>> (max_port_num) NAT_FIN_counter;
    // register<bit<32>> (max_port_num) host_ip;
    // register<bit<16>>  (max_port_num) host_port;


    action drop() {
        // drop the packet
        mark_to_drop(standard_metadata);
    }
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
    }
    table ipv4_lookup{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
           ipv4_forward;
           drop;
           multicast;
        }
        size = 1024;
        default_action = multicast;
    }

    apply {
        if(hdr.tcp.isValid()){
            bit<9> src_port=standard_metadata.ingress_port;
            bit<32> index;
            bit<32> base=0;
            bit<32> src_ip=hdr.ipv4.srcAddr;
            bit<32> dst_ip=hdr.ipv4.dstAddr;
            bit<16> src_tcp_port=hdr.tcp.srcPort;
            bit<16> dst_tcp_port=hdr.tcp.dstPort;
            if(src_port!=3){
                // hash(index, HashAlgorithm.crc32, base, src_tcp_port, max_port_num - 1);
                bit<32> user;
                NAT_IP_table.read(user,(bit<32>)src_tcp_port);
                if(user==0){
                    NAT_IP_table.write((bit<32>)src_tcp_port,hdr.ipv4.srcAddr);
                    NAT_Port_table.write((bit<32>)src_tcp_port,src_tcp_port);
                    hdr.ipv4.srcAddr=PUB_IP;
                }
                else if(user==hdr.ipv4.srcAddr){
                    bit<32> num;
                    NAT_FIN_counter.read(num,(bit<32>)src_tcp_port);
                    if(num==2){
                        NAT_IP_table.write((bit<32>)src_tcp_port,0);
                        NAT_Port_table.write((bit<32>)src_tcp_port,0);
                        NAT_FIN_counter.write((bit<32>)src_tcp_port,0);
                    }
                    if(hdr.tcp.ctl_flag==0x011){
                        NAT_FIN_counter.write((bit<32>)src_tcp_port,num+1);
                    }
                    hdr.ipv4.srcAddr=PUB_IP;
                }
                else{
                    bit<32> u1;
                    bit<32> u2;
                    bit<32> u3;
                    bit<32> u4;
                    NAT_IP_table.read(u1,(bit<32>)src_tcp_port+1);
                    NAT_IP_table.read(u2,(bit<32>)src_tcp_port+2);
                    NAT_IP_table.read(u3,(bit<32>)src_tcp_port-1);
                    NAT_IP_table.read(u4,(bit<32>)src_tcp_port-2);
                    if(u1==0){
                        NAT_IP_table.write((bit<32>)src_tcp_port+1,hdr.ipv4.srcAddr);
                        NAT_Port_table.write((bit<32>)src_tcp_port+1,src_tcp_port);
                        hdr.ipv4.srcAddr=PUB_IP;
                        hdr.tcp.srcPort=src_tcp_port+1;
                    }
                    else if(u2==0){
                        NAT_IP_table.write((bit<32>)src_tcp_port+2,hdr.ipv4.srcAddr);
                        NAT_Port_table.write((bit<32>)src_tcp_port+2,src_tcp_port);
                        hdr.ipv4.srcAddr=PUB_IP;
                        hdr.tcp.srcPort=src_tcp_port+2;
                    }
                    else if(u3==0){
                        NAT_IP_table.write((bit<32>)src_tcp_port+3,hdr.ipv4.srcAddr);
                        NAT_Port_table.write((bit<32>)src_tcp_port+3,src_tcp_port);
                        hdr.ipv4.srcAddr=PUB_IP;
                        hdr.tcp.srcPort=src_tcp_port-1;
                    }
                    else if(u4==0){
                        NAT_IP_table.write((bit<32>)src_tcp_port+4,hdr.ipv4.srcAddr);
                        NAT_Port_table.write((bit<32>)src_tcp_port+4,src_tcp_port);
                        hdr.ipv4.srcAddr=PUB_IP;
                        hdr.tcp.srcPort=src_tcp_port-2;
                    }
                    else{
                        drop();
                    }
                }
            }
            if(src_port==3){
                // hash(index, HashAlgorithm.crc32, base, {src_ip,src_tcp_port}, max_port_num-1);
                NAT_IP_table.read(hdr.ipv4.dstAddr,(bit<32>)dst_tcp_port);
                NAT_Port_table.read(hdr.tcp.dstPort,(bit<32>)dst_tcp_port);
                bit<32> num;
                if(hdr.tcp.ctl_flag==0x011){
                    NAT_FIN_counter.read(num,(bit<32>)dst_tcp_port);
                    NAT_FIN_counter.write((bit<32>)dst_tcp_port,num+1);
                }
            }
            ipv4_lookup.apply();
        }
        else {
            ipv4_lookup.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    apply {  
        if (standard_metadata.egress_port == standard_metadata.ingress_port) drop();

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
        update_checksum_with_payload(
        hdr.tcp.isValid(),
            {
            //tcp checksum is usually calculated with the following fields
            //pseudo header+tcp header+tcp payload
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            meta.tot_length,   // 16 bit of tcp length + payload length in bytes
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seq_num,
            hdr.tcp.ack_num,
            hdr.tcp.data_offset,
            hdr.tcp.reserved,
            hdr.tcp.ctl_flag,
            hdr.tcp.window_size,
            hdr.tcp.urgent_num,
            hdr.tcp_options_padding.padding
        }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_padding);
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