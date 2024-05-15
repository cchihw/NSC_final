/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8>  TYPE_UDP = 0x11;
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

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;

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


header_union l4_t{
    udp_t udp;
    tcp_t tcp;
}
struct metadata {
    bit<16> tcp_length;
    bit<16> tot_length;
    bit<16> udp_length;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    l4_t         l4;
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
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        transition consume_remaining_tcp_hdr_and_accept;
    }

    state consume_remaining_tcp_hdr_and_accept {
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
            TYPE_UDP  : parse_udp;
            TYPE_TCP  : parse_tcp;
            default   : accept;
        }
    }
    state parse_udp{
        packet.extract(hdr.l4.udp);
        meta.udp_length = hdr.ipv4.totalLen-20;
        transition accept;
    }
    state parse_tcp{
        packet.extract(hdr.l4.tcp);
        meta.tcp_length = (bit<16>)hdr.l4.tcp.data_offset * 4;
        meta.tot_length = hdr.ipv4.totalLen-20;
        // Tcp_option_parser.apply(packet, hdr.l4.tcp.data_offset,
        //                         hdr.l4.tcp_options_padding);
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
    register<bit<16>> (max_port_num) port_counter;
    register<bit<32>> (max_port_num) out_in_IP;
    register<bit<16>> (max_port_num) out_in_port;
    register<bit<16>> (max_port_num) ip_port_to_out;
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
    action register_modify(bit<32> index, bit<16> map_out_port, bit<32> src_ip, bit<16> src_tcp_port){
        out_in_IP.write((bit<32>)map_out_port,src_ip);
        out_in_port.write((bit<32>)map_out_port,src_tcp_port);
        ip_port_to_out.write(index,map_out_port);
        hdr.ipv4.srcAddr=PUB_IP;
        hdr.l4.tcp.srcPort=map_out_port;
    }
    apply {
        if((hdr.ipv4.dstAddr>>8)==0x0a0001){
            ipv4_lookup.apply();
        }
        else if(hdr.l4.tcp.isValid() || hdr.l4.udp.isValid()){
            bit<9> src_port=standard_metadata.ingress_port;
            bit<32> index;
            bit<32> base=0;
            bit<32> src_ip=hdr.ipv4.srcAddr;
            bit<32> dst_ip=hdr.ipv4.dstAddr;
            bit<16> src_tcp_port;
            bit<16> dst_tcp_port;
            bit<16> map_in_port;
            if(hdr.l4.tcp.isValid()){
                src_tcp_port=hdr.l4.tcp.srcPort;
                dst_tcp_port=hdr.l4.tcp.dstPort;
            }
            else{
                src_tcp_port=hdr.l4.udp.srcPort;
                dst_tcp_port=hdr.l4.udp.dstPort;
            }
            if((src_port<3) && src_tcp_port==80){
                hdr.ipv4.srcAddr=PUB_IP;
            }
            else if(src_port>2 && dst_tcp_port==80){
                hdr.ipv4.dstAddr=h1_IP;
                hdr.l4.tcp.dstPort=80;
            }
            else if(src_port<3){
                hash(index,HashAlgorithm.crc32,base,{src_ip,src_tcp_port},max_port_num-1);
                bit<16> map_out_port;
                ip_port_to_out.read(map_out_port,index);
                if(map_out_port==0){//new {ip,port} pair
                    bit<16> next_port;
                    port_counter.read(next_port,0);
                    if(next_port==0){
                        next_port=10000;
                        map_out_port=next_port;
                        port_counter.write(0,next_port+1);
                        register_modify(index,map_out_port,src_ip,src_tcp_port);
                    }
                    else{
                        map_out_port=next_port;
                        if(next_port<65500){
                            port_counter.write(0,next_port+1);
                        }
                        else{
                            port_counter.write(0,10000);
                        }
                        register_modify(index,map_out_port,src_ip,src_tcp_port);
                    }
                }
                else{
                    hdr.ipv4.srcAddr=PUB_IP;
                }
                if(hdr.l4.tcp.isValid()){
                    hdr.l4.tcp.srcPort=map_out_port;
                }
                else{
                    hdr.l4.udp.srcPort=map_out_port;
                }
            }
            else if(src_port>2){
                if(hdr.ipv4.dstAddr==PUB_IP){
                    out_in_IP.read(hdr.ipv4.dstAddr,(bit<32>)dst_tcp_port);
                    out_in_port.read(map_in_port,(bit<32>)dst_tcp_port);
                    if(hdr.l4.tcp.isValid()){
                        hdr.l4.tcp.dstPort=map_in_port;
                    }
                    else{
                        hdr.l4.udp.dstPort=map_in_port;
                    }
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
        hdr.l4.tcp.isValid(),
            {
            //tcp checksum is usually calculated with the following fields
            //pseudo header+tcp header+tcp payload
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            meta.tot_length,   // 16 bit of tcp length + payload length in bytes
            hdr.l4.tcp.srcPort,
            hdr.l4.tcp.dstPort,
            hdr.l4.tcp.seq_num,
            hdr.l4.tcp.ack_num,
            hdr.l4.tcp.data_offset,
            hdr.l4.tcp.reserved,
            hdr.l4.tcp.ctl_flag,
            hdr.l4.tcp.window_size,
            hdr.l4.tcp.urgent_num
        }, hdr.l4.tcp.checksum, HashAlgorithm.csum16);
        update_checksum_with_payload(
        hdr.l4.udp.isValid(),
            {
            //tcp checksum is usually calculated with the following fields
            //pseudo header+tcp header+tcp payload
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            hdr.l4.udp.length,   // 16 bit of tcp length + payload length in bytes
            hdr.l4.udp.srcPort,
            hdr.l4.udp.dstPort,
            hdr.l4.udp.length
        }, hdr.l4.udp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.l4.udp);
        packet.emit(hdr.l4.tcp);
        // packet.emit(hdr.l4.tcp_options_padding);
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