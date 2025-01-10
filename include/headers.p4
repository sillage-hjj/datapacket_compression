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
    bit<3> huffman_bit;
    bit<10> extension_bit;
    bit<4> extension_length;
    bit<4>  count;
}

struct huffman_1t {
    bit<3> huffman_bit;
}

struct huffman_2t {
    bit<3> huffman_bit;
    bit<4> extension_bit;
}

struct huffman_3t {
    bit<3> huffman_bit;
    bit<9> extension_bit;
}
struct huffman_4t {
    bit<3> huffman_bit;
    bit<10> extension_bit;
}

struct learn_11t {
    bit<8>  time_stamps;
    huffman_1t haffman;
}
struct learn_12t {
    bit<8>  time_stamps;
    huffman_2t haffman;
}
struct learn_13t {
    bit<8>  time_stamps;
    huffman_3t haffman;
}
struct learn_14t {
    bit<8>  time_stamps;
    huffman_4t haffman;
}

struct learn_21t {
    bit<16> time_stamps;
    huffman_1t haffman;
}
struct learn_22t {
    bit<16> time_stamps;
    huffman_2t haffman;
}
struct learn_23t {
    bit<16> time_stamps;
    huffman_3t haffman;
}
struct learn_24t {
    bit<16> time_stamps;
    huffman_4t haffman;
}

struct learn_31t {
    bit<24> time_stamps;
    huffman_1t haffman;
}
struct learn_32t {
    bit<24> time_stamps;
    huffman_2t haffman;
}
struct learn_33t {
    bit<24> time_stamps;
    huffman_3t haffman;
}
struct learn_34t {
    bit<24> time_stamps;
    huffman_4t haffman;
}

struct learn_41t {
    bit<30> time_stamps;
    huffman_1t haffman;
}
struct learn_42t {
    bit<30> time_stamps;
    huffman_2t haffman;
}
struct learn_43t {
    bit<30> time_stamps;
    huffman_3t haffman;
}
struct learn_44t {
    bit<30> time_stamps;
    huffman_4t haffman;
}

struct learn_51t {
    bit<36> time_stamps;
    huffman_1t haffman;
}
struct learn_52t {
    bit<36> time_stamps;
    huffman_2t haffman;
}
struct learn_53t {
    bit<36> time_stamps;
    huffman_3t haffman;
}
struct learn_54t {
    bit<36> time_stamps;
    huffman_4t haffman;
}

struct learn_61t {
    bit<42> time_stamps;
    huffman_1t haffman;
}
struct learn_62t {
    bit<42> time_stamps;
    huffman_2t haffman;
}
struct learn_63t {
    bit<42> time_stamps;
    huffman_3t haffman;
}
struct learn_64t {
    bit<42> time_stamps;
    huffman_4t haffman;
}

struct metadata {
    learn_t learn;
    learn_11t learn_11;
    learn_12t learn_12;
    learn_13t learn_13;
    learn_14t learn_14;
    learn_21t learn_21;
    learn_22t learn_22;
    learn_23t learn_23;
    learn_24t learn_24;
    learn_31t learn_31;
    learn_32t learn_32;
    learn_33t learn_33;
    learn_34t learn_34;
    learn_41t learn_41;
    learn_42t learn_42;
    learn_43t learn_43;
    learn_44t learn_44;
    learn_51t learn_51;
    learn_52t learn_52;
    learn_53t learn_53;
    learn_54t learn_54;
    learn_61t learn_61;
    learn_62t learn_62;
    learn_63t learn_63;
    learn_64t learn_64;
    /* empty */
}
