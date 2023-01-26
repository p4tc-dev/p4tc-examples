/* -*- P4_16 -*- */

#include <pna.p4>

#define PORT_TABLE_SIZE 128

/*
 * Standard ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

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
//$TC p4runtime create redirect_l2/table/MainControlImpl/nh_table \
//    output_port eth0 nh_mac 00:11:22:33:44:55 nh_src AA:BB:CC:DD:EE:FF
   action send_nh(PortId_t port, bit<48> dmac, bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
	hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
   }
 
   action drop() {
        drop_packet();
   }

    table nh_table {
        key = {
            standard_metadata.ingress_spec : exact; @name("input_port")
        }
        actions = {
            send_nh;
            drop;
        }
        size = PORT_TABLE_SIZE;
        const default_action = drop;
    }

    apply {
        redirect_l2.apply();
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
