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
		meta.learn.extension_len = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_1(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_len = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_2(bit<2> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_len = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_3(bit<2> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_len = 0;  // 仅1个包长度，不需要扩展码
	}

	action set_huffman_bit_4(bit<5> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 55;
		meta.learn.extension_len = 4; // 使用4位扩展码
	}

	action set_huffman_bit_5(bit<3> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 73;
		meta.learn.extension_len = 4;  // 使用4位扩展码
	}

	action set_huffman_bit_6(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		meta.learn.extension_bit = standard_metadata.packet_length - 89;
		meta.learn.extension_len = 9;  // 使用9位扩展码
	}

	action set_huffman_bit_7(bit<4> huffman) {
		meta.learn.huffman_bit = huffman;
		if(standard_metadata.packet_length >= 1475) meta.learn.extension_bit = standard_metadata.packet_length - 602;
		else meta.learn.extension_bit = standard_metadata.packet_length - 601;
		meta.learn.extension_len = 10;  // 使用10位扩展码
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
		if(meta.learn.extension_len == 0){
			meta.learn11.time_stamps = standard_metadata.ingress_global_timestamp[7:0];
			meta.learn11.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_11t>(1, meta.learn11);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn12.time_stamps = standard_metadata.ingress_global_timestamp[7:0];
			meta.learn12.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn12.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_12t>(1, meta.learn12);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn13.time_stamps = standard_metadata.ingress_global_timestamp[7:0];
			meta.learn13.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn13.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_13t>(1, meta.learn13);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn14.time_stamps = standard_metadata.ingress_global_timestamp[7:0];
			meta.learn14.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn14.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_14t>(1, meta.learn14);
		}
    }

    action digest_2t() {
        // encoded_packet_length = bit<3> 2;
		if(meta.learn.extension_len == 0){
			meta.learn21.time_stamps = standard_metadata.ingress_global_timestamp[15:0];
			meta.learn21.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_21t>(1, meta.learn21);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn22.time_stamps = standard_metadata.ingress_global_timestamp[15:0];
			meta.learn22.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn22.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_22t>(1, meta.learn22);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn23.time_stamps = standard_metadata.ingress_global_timestamp[15:0];
			meta.learn23.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn23.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_23t>(1, meta.learn23);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn24.time_stamps = standard_metadata.ingress_global_timestamp[15:0];
			meta.learn24.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn24.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_24t>(1, meta.learn24);
		}
    }
	

    action digest_3t() {
        // encoded_packet_length = bit<3> 2;
		if(meta.learn.extension_len == 0){
			meta.learn31.time_stamps = standard_metadata.ingress_global_timestamp[23:0];
			meta.learn31.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_31t>(1, meta.learn31);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn32.time_stamps = standard_metadata.ingress_global_timestamp[23:0];
			meta.learn32.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn32.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_32t>(1, meta.learn32);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn33.time_stamps = standard_metadata.ingress_global_timestamp[23:0];
			meta.learn33.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn33.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_33t>(1, meta.learn33);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn34.time_stamps = standard_metadata.ingress_global_timestamp[23:0];
			meta.learn34.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn34.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_34t>(1, meta.learn34);
		}
    }

    action digest_4t() {
        // encoded_packet_length = bit<3> 2;
		if(meta.learn.extension_len == 0){
			meta.learn41.time_stamps = standard_metadata.ingress_global_timestamp[31:0];
			meta.learn41.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_41t>(1, meta.learn41);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn42.time_stamps = standard_metadata.ingress_global_timestamp[31:0];
			meta.learn42.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn42.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_42t>(1, meta.learn42);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn43.time_stamps = standard_metadata.ingress_global_timestamp[31:0];
			meta.learn43.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn43.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_43t>(1, meta.learn43);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn44.time_stamps = standard_metadata.ingress_global_timestamp[31:0];
			meta.learn44.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn44.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_44t>(1, meta.learn44);
		}
    }

    action digest_5t() {
        // encoded_packet_length = bit<3> 2;
		if(meta.learn.extension_len == 0){
			meta.learn51.time_stamps = standard_metadata.ingress_global_timestamp[39:0];
			meta.learn51.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_51t>(1, meta.learn51);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn52.time_stamps = standard_metadata.ingress_global_timestamp[39:0];
			meta.learn52.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn52.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_52t>(1, meta.learn52);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn53.time_stamps = standard_metadata.ingress_global_timestamp[39:0];
			meta.learn53.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn53.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_53t>(1, meta.learn53);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn54.time_stamps = standard_metadata.ingress_global_timestamp[39:0];
			meta.learn54.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn54.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_54t>(1, meta.learn54);
		}
    }

    action digest_6t() {
        // encoded_packet_length = bit<3> 2;
		if(meta.learn.extension_len == 0){
			meta.learn61.time_stamps = standard_metadata.ingress_global_timestamp[47:0];
			meta.learn61.huffman.huffman_bit = meta.learn.huffman_bit;
			digest<learn_61t>(1, meta.learn61);
		}
		else if(meta.learn.extension_len == 4){
			meta.learn62.time_stamps = standard_metadata.ingress_global_timestamp[47:0];
			meta.learn62.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn62.huffman.extension_bit = meta.learn.extension_bit[4:0];
			digest<learn_62t>(1, meta.learn62);
		}
		else if(meta.learn.extension_len == 9){
			meta.learn63.time_stamps = standard_metadata.ingress_global_timestamp[47:0];
			meta.learn63.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn63.huffman.extension_bit = meta.learn.extension_bit[9:0];
			digest<learn_63t>(1, meta.learn63);
		}
		else if(meta.learn.extension_len == 10){
			meta.learn64.time_stamps = standard_metadata.ingress_global_timestamp[47:0];
			meta.learn64.huffman.huffman_bit = meta.learn.huffman_bit;
			meta.learn64.huffman.extension_bit = meta.learn.extension_bit[10:0];
			digest<learn_64t>(1, meta.learn64);
		}
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