#include <core.p4>
#include "pna.p4"

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
    IPv4Address srcAddr;
    IPv4Address dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

// User-defined struct containing all of those headers parsed in the
// main parser.
struct headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

parser MainParserImpl(
    packet_in pkt,
    out   headers_t hdr,
    inout metadata_t meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800  : parse_ipv4;
            default : accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6       : parse_tcp;
            default : accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control PreControlImpl(
    in    headers_t hdr,
    inout metadata_t meta,
    in    pna_pre_input_metadata_t istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply {
        // No IPsec decryption for this example program, so pre
        // control does nothing.
    }
}

control MainControlImpl(
    inout headers_t hdr,                 // from main parser
    inout metadata_t meta,               // from main parser, to "next block"
    in    pna_main_input_metadata_t istd,
    inout pna_main_output_metadata_t ostd)
{
    action ct_tcp_default_miss() {
        add_entry();
    }

    table ct_tcp_table {
        key = {
            istd.direction : exact;
            hdr.ipv4.srcAddr : exact; @name("ipv4_addr_0")  @type("ipv4");
            hdr.ipv4.dstAddr : exact; @name("ipv4_addr_1")  @type("ipv4");
            hdr.ipv4.protocol : exact;
            hdr.tcp.srcPort : exact; @name("tcp_port_0")  @type("be16");
            hdr.tcp.dstPort : exact; @name("tcp_port_1")  @type("be16");
        }
        actions = {
            @defaultonly ct_tcp_default_miss;
        }
        default_action = ct_tcp_default_miss;
    }

    apply {
	do_add_on_miss = false;
        if (hdr.ipv4.isValid() && hdr.tcp.isValid())
        {
            ct_tcp_table.apply();
        }
    }
}

control MainDeparserImpl(
    packet_out pkt,
    in headers_t hdr,                    // from main control
    in metadata_t meta,                  // from main control
    in pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

// BEGIN:Package_Instantiation_Example
PNA_NIC(
    MainParserImpl(),
    PreControlImpl(),
    MainControlImpl(),
    MainDeparserImpl()
    ) main;
// END:Package_Instantiation_Example
