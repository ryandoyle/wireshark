/* packet-elasticsearch.c
 *
 * Routines for disecting Elasticsearch
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <epan/packet.h>

#define ELASTICSEARCH_DISCOVERY_PORT 54328;
// ^ wtf the above doesn't work
#define ELASTICSEARCH_INTERNAL_HEADER 0x01090804

static int proto_elasticsearch = -1;

static gint ett_elasticsearch = -1;

void proto_register_elasticsearch(void) {

	static gint *ett[] = {
			&ett_elasticsearch,
	};

	proto_elasticsearch = proto_register_protocol(
			"Elasticsearch",
			"Elasticsearch",
			"elasticsearch");

	proto_register_subtree_array(ett, array_length(ett));

}

static void dissect_elasticsearch_zen_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset){

//	guint32 internal_header;
//	guint32 version;

	/* Let the user know its a discovery packet */
	col_set_str(pinfo->cinfo, COL_INFO, "Zen Ping: ");


	/* Add the internal header */
//	proto_tree_add_bits_item();
//	offset += 4;

	(void)offset;
	(void)tree;
	(void)tvb;

}

static void dissect_elasticsearch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
	proto_item *root_elasticsearch_item;
	proto_tree *elasticsearch_tree;

	guint32 internal_header;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Elasticsearch");
	col_clear(pinfo->cinfo, COL_INFO);

	root_elasticsearch_item = proto_tree_add_item(tree, proto_elasticsearch, tvb, 0, -1, ENC_NA);
	elasticsearch_tree = proto_item_add_subtree(root_elasticsearch_item,ett_elasticsearch);


	internal_header = tvb_get_ntohl(tvb,offset);
	if(internal_header == ELASTICSEARCH_INTERNAL_HEADER){
		dissect_elasticsearch_zen_ping(tvb,pinfo,elasticsearch_tree,offset);
	}



	(void)tvb;
	(void)pinfo;
	(void)tree;

}

void proto_reg_handoff_elasticsearch(void) {

	static dissector_handle_t elasticsearch_handle;

	elasticsearch_handle = create_dissector_handle(dissect_elasticsearch, proto_elasticsearch);
	dissector_add_uint("udp.port", 54328, elasticsearch_handle); // FIXME: Use the #define macro for the port

}






