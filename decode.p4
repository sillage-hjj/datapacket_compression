/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"



/********************CHECKSUM VERIFICATION********************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply { }
}

/*********************INGRESS PROCESSING**********************/

control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {
	
	register<bit<4>>(1) counts;
	register<bit<48>>(1) timestamp_tmp;
	
	action drop(){
		mark_to_drop();
	}

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
		standard_metadata.egress_spec = port;
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ipv4_lpm {
		key={
			hdr.ipv4.dstAddr: lpm;
		}
		actions={
			ipv4_forward;
			drop;
			NoAction;
		}
		size=1024;
		default_action=drop();
	}
	/*****divid neiber number and separete them into group, each group contain 16 item ******/
	/*****this design ensure that transmission error only affect current window*/
	action mac_learn(){
		bit<48> tmp;
		couns.read(meta.learn.count, 0);

		meta.learn.count = meta.learn.count + 1;

		if(meta.learn.count == 15){
			meta.learn.count = 0;
		}

		counts.write(0, meta.learn.count);

		timestamp_tmp.read(tmp, 0);
		if(meta.learn.count != 0){
			meta.learn.time_stamps = (standard_metadata.ingress_global_timestamp - tmp);
		}
		else{
			meta.learn.time_stamps = standard_metadata.ingress_global_timestamp;
		}
		timestamp_tmp.write(0, standard_metadata.ingress_global_timestamp);
	}

	action set_huffman_bit_0(bit<3> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_1(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_2(bit<2> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_3(bit<2> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_4(bit<5> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 55;
		meta.learn.extension_len = 4; // 使用4位扩展码
	}

	action set_huffman_bit_5(bit<3> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 73;
		meta.learn.extension_bit = 4;  // 使用4位扩展码
	}

	action set_huffman_bit_6(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 89;
		meta.learn.extension_bit = 9;  // 使用9位扩展码
	}

	action set_huffman_bit_7(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		if(standard_metadata.packet_length >= 1475) meta.learn.extension_bit = standard_metadata.packet_length - 602;
		else meta.learn.extension_bit = standard_metadata.packet_length - 601;
		meta.learn.extension_bit = 10;  // 使用10位扩展码
	}


	table huffman_bit_table_0 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_0;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			54: set_huffman_bit_0(0b000);
		}
	}

	table huffman_bit_table_1 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_1;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			60: set_huffman_bit_1(0b1001);
		}
	}

	table huffman_bit_table_2 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_2;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			66: set_huffman_bit_2(0b01);
		}
	}

	table huffman_bit_table_3 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_3;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			1474: set_huffman_bit_3(0b10);
		}
	}

	table huffman_bit_table_4 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_4;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			55..72: set_huffman_bit_4(0b00101);
		}
	}

	table huffman_bit_table_5 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_5;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			73..88: set_huffman_bit_5(0b101);
		}
	}

	table huffman_bit_table_6 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_6;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			89..600: set_huffman_bit_6(0b1000);
		}
	}

	table huffman_bit_table_7 {
		key = {
			standard_metadata.packet_length: range;
		}
		actions = {
			set_huffman_bit_7;
		}
		size = 1024;
		default_action = NoAction;
		
		const entries = {
			601..1473: set_huffman_bit_7(0b0011);
			1475..1625: set_huffman_bit_7(0b0011);
		}
	}

	action digest_1t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn1.time_stamps = standard_metadata.ingress_global_timestamp[7:0];
        meta.learn1.packet_length = meta.learn.packet_length;
        digest<learn_1t>(1, meta.learn1);
    }

    action digest_2t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn2.time_stamps = standard_metadata.ingress_global_timestamp[15:0];
        meta.learn2.packet_length = meta.learn.packet_length;
        digest<learn_2t>(1, meta.learn2);
    }

    action digest_3t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn3.time_stamps = standard_metadata.ingress_global_timestamp[23:0];
        meta.learn3.packet_length = meta.learn.packet_length;
        digest<learn_3t>(1, meta.learn3);
    }

    action digest_4t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn4.time_stamps = standard_metadata.ingress_global_timestamp[31:0];
        meta.learn4.packet_length = meta.learn.packet_length;
        digest<learn_4t>(1, meta.learn4);
    }

    action digest_5t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn5.time_stamps = standard_metadata.ingress_global_timestamp[39:0];
        meta.learn5.packet_length = meta.learn.packet_length;
        digest<learn_5t>(1, meta.learn5);
    }

    action digest_6t() {
        // encoded_packet_length = bit<3> 2;
        meta.learn6.time_stamps = standard_metadata.ingress_global_timestamp[47:0];
        meta.learn6.packet_length = meta.learn.packet_length;
        digest<learn_6t>(1, meta.learn6);
    }
	
    table d_info {
        key = {
            meta.learn.time_stamps: range;
        }
        
        actions = {
            digest_1t;
            digest_2t;
            digest_3t;
            digest_4t;
            digest_5t;
            digest_6t;
            NoAction;
        }
        size = 2048;
        default_action = NoAction;

        const entries= {
            0x000000000000..0x0000000000ff : digest_1t();
            0x000000000100..0x00000000ffff : digest_2t();
            0x000000010000..0x000000ffffff : digest_3t();
            0x000001000000..0x0000ffffffff : digest_4t();
            0x000100000000..0x00ffffffffff : digest_5t();
            0x010000000000..0xffffffffffff : digest_6t();
        }
    }

	apply {
		mac_learn();
		huffman_bit_table_0.apply();
		huffman_bit_table_1.apply();
		huffman_bit_table_2.apply();
		huffman_bit_table_3.apply();
		huffman_bit_table_4.apply();
		huffman_bit_table_5.apply();
		huffman_bit_table_6.apply();
		huffman_bit_table_7.apply();
		d_info.apply();
		if(hdr.ipv4.isValid()) {
			ipv4_lpm.apply();
		}
	}
}

/*********************EGRESS PROCESSING***********************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {
	apply {}
}

/*******************CHECKSUM COMPUTATION*********************/

control	MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply{
		update_checksum(
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
              	hdr.ipv4.dstAddr},
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16);
	}
}

/**************************SWITCH****************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;