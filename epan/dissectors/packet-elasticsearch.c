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

static int proto_elasticsearch = -1;

void proto_register_elasticsearch(void) {
	proto_elasticsearch = proto_register_protocol(
			"Elasticsearch",
			"Elasticsearch",
			"elasticsearch"
			);

}

static void dissect_elasticsearch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ELASTICSEARCH");
	col_clear(pinfo->cinfo, COL_INFO);

	(void)tvb;
	(void)pinfo;
	(void)tree;

}

void proto_reg_handoff_elasticsearch(void) {

	static dissector_handle_t elasticsearch_handle;

	elasticsearch_handle = create_dissector_handle(dissect_elasticsearch, proto_elasticsearch);
	dissector_add_uint("udp.port", 54328, elasticsearch_handle); // FIXME: Use the #define macro for the port

}






