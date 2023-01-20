/* -*- P4_16 -*- */

#include <pna.p4>

#define L3_TABLE_SIZE 2048
#define NET_TO_HOST 1w0
#define HOST_TO_NET 1w1

#define RxPkt(meta) (meta.common.direction == NET_TO_HOST)
#define TxPkt(meta) (meta.common.direction == HOST_TO_NET)

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    IPv4Address src_ip;
    IPv4Address dst_ip;
}

struct parsed_headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
}

struct user_rx_host_metadata_t { };
struct user_tx_host_metadata_t { };

control PreControlImpl(
    in    parsed_headers_t hdrs,
    inout user_metadata_t meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply {
        // No IPsec decryption for this example program, so pre
        // control does nothing.
    }
}

control MainControlImpl(
    inout parsed_headers_t  hdrs,
    inout user_metadata_t user_meta,
    inout standard_metadata_t meta,
    out user_rx_host_metadata_t user_rx_host_meta,
    in user_tx_host_metadata_t user_tx_host_meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd)
{
// how do we define "PortId_t" for send() as a "dev" i.e @as_dev_type;
    action send(PortId_t port) {
        send_to_port(port);
    }
    action drop() {
        drop_packet();
    }

    table l3_match_rx {
        key = {
            hdrs.ipv4.dst_ip : exact; @name("dstAddr")
        }
        actions = {
            send;
            drop;
        }
        size = L3_TABLE_SIZE;
        const default_action = drop;
    }

    apply {
        if (RxPkt(meta) && hdrs.ipv4.isValid() && hdr.tcp.isValid()) {
            l3_match_rx.apply();
        }
    }
}

control MainDeparserImpl(
    packet_out pkt,
    in    parsed_headers_t  hdrs,
    in    user_metadata_t main_user_meta,
    in    pna_main_output_metadata_t ostd)
{
    apply { }
}

PNA_NIC(IDPFParser(), PreControlImpl(), MainControlImpl(), MainDeparserImpl()) main;
