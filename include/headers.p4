/* -*- P4_16 -*- */
const bit<16> TYPE_IPV4 = 0x800;

/********************HEADER***********************/
typedef bit<9> egressSpec_t;
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

header tcp_t {
    fields {
        srcPort         : 16;
        dstPort         : 16;
        seqNo           : 32;
        ackNo           : 32;
        dataOffset      :  4;
        reserved        :  3;
        ns              :  1;
        cwr             :  1;
        ece             :  1;
        urg             :  1;
        ack             :  1;
        psh             :  1;
        rst             :  1;
        syn             :  1;
        fin             :  1;
        window          : 16;
        checksum        : 16;
        urgentPointer   : 16;
    }
}

// header udp_t {
//     fields {
//         srcPort     : 16;
//         dstPort     : 16;
//         len         : 16;
//         checksum    : 16;
//     }
// }

// header icmp_t {
//     fields {
//         icmpType    :  8;
//         code        :  8;
//         checksum    : 16;
//         rest        : 32;
//     }
// }

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;    
}

struct learn_t {
    bit<48> time_stamps;
    bit<3>  packet_length;
    bit<4>  count;
}

struct learn_1t {
    bit<8>  time_stamps;
    bit<3>  packet_length;
}

struct learn_2t {
    bit<16> time_stamps;
    bit<3>  packet_length;
}
struct learn_3t {
    bit<24> time_stamps;
    bit<3>  packet_length;
}
struct learn_4t {
    bit<30> time_stamps;
    bit<3>  packet_length;
}
struct learn_5t {
    bit<36> time_stamps;
    bit<3>  packet_length;
}

struct learn_6t {
    bit<42> time_stamps;
    bit<3>  packet_length;
}

struct huffman {
    bit<16> packet_length;
    bit<16> packet_huffman;
    bit<4>  packet_extension;
}

struct metadata {
    huffman huffman;
    learn_t learn;
    learn_1t learn_1;
    learn_2t learn_2;
    learn_3t learn_3;
    learn_4t learn_4;
    learn_5t learn_5;
    learn_6t learn_6;
    /* empty */
}
