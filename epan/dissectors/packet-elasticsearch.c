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

static int hf_elasticsearch_internal_header = -1;
static int hf_elasticsearch_version = -1;

static gint ett_elasticsearch = -1;

void proto_register_elasticsearch(void) {

    static hf_register_info hf[] = {
        { &hf_elasticsearch_internal_header,
          { "Internal header", "elasticsearch.internal_header",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_version,
          { "Version", "elasticsearch.version",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
    };

	static gint *ett[] = {
			&ett_elasticsearch,
	};

	proto_elasticsearch = proto_register_protocol(
			"Elasticsearch",
			"Elasticsearch",
			"elasticsearch");

    proto_register_field_array(proto_elasticsearch, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

static int bytes_in_vint(tvbuff_t *tvb, int offset){
    int bytes = 1;
    guint8 byte = tvb_get_guint8(tvb, offset);
    while((byte & 0x80) != 0 && bytes < 6){
        byte = tvb_get_guint8(tvb, offset + bytes);
        bytes += 1;
    }
    if(bytes > 5){
        // Variable length encoded ints should never be larger than this! 
        return -1;
    }
    return bytes;
}

static int read_vint(tvbuff_t *tvb, int offset){
    guint8 b = tvb_get_guint8(tvb, offset);
    int i = b & 0x7F;
    if ((b & 0x80) == 0) {
        return i;
    }
    b = tvb_get_guint8(tvb, offset+1); 
    i |= (b & 0x7F) << 7;
    if ((b & 0x80) == 0) {
        return i;
    }
    b = tvb_get_guint8(tvb, offset+2); 
    i |= (b & 0x7F) << 14;
    if ((b & 0x80) == 0) {
        return i;
    }
    b = tvb_get_guint8(tvb, offset+3); 
    i |= (b & 0x7F) << 21;
    if ((b & 0x80) == 0) {
        return i;
    }
    b = tvb_get_guint8(tvb, offset+4); 
    // FIXME: need some assertion like assert (b & 0x80) == 0; 
    return i | ((b & 0x7F) << 28);

}

static void dissect_elasticsearch_zen_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset){
    int vint_length;
    int version;

	/* Let the user know its a discovery packet */
	col_set_str(pinfo->cinfo, COL_INFO, "Zen Ping: ");


	/* Add the internal header */
	proto_tree_add_item(tree, hf_elasticsearch_internal_header, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

    /* Add the variable length encoded version string */
    vint_length = bytes_in_vint(tvb, offset);
    version = read_vint(tvb, offset);
    proto_tree_add_uint(tree, hf_elasticsearch_version, tvb, offset, vint_length, version);
    offset += vint_length;

	(void)offset;
	(void)tree;
	(void)tvb;
    (void)vint_length;
    (void)version;

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






