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


typedef struct {
    int length;
    int value;
} vint_t;

typedef struct {
    vint_t vint_length;
    int length; 
    char *value;
} vstring_t;

static int proto_elasticsearch = -1;

static int hf_elasticsearch_internal_header = -1;
static int hf_elasticsearch_version = -1;
static int hf_elasticsearch_ping_request_id = -1;
static int hf_elasticsearch_cluster_name= -1;
static int hf_elasticsearch_node_name = -1;
static int hf_elasticsearch_node_id = -1;
static int hf_elasticsearch_host_name = -1;
static int hf_elasticsearch_host_address = -1;

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
        { &hf_elasticsearch_ping_request_id,
          { "Ping ID", "elasticsearch.ping_request_id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_cluster_name,
          { "Cluster name", "elasticsearch.cluster_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_node_name,
          { "Node name", "elasticsearch.node_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_node_id,
          { "Node ID", "elasticsearch.node_id",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_host_name,
          { "Hostname", "elasticsearch.host_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_host_address,
          { "Hostname", "elasticsearch.host_address",
            FT_STRING, BASE_NONE,
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

static vint_t read_vint(tvbuff_t *tvb, int offset){
    vint_t vint;
    guint8 b = tvb_get_guint8(tvb, offset);
    vint.value = b & 0x7F;
    if ((b & 0x80) == 0) {
        vint.length = 1;
        return vint;
    }
    b = tvb_get_guint8(tvb, offset+1); 
    vint.value |= (b & 0x7F) << 7;
    if ((b & 0x80) == 0) {
        vint.length = 2;
        return vint;
    }
    b = tvb_get_guint8(tvb, offset+2); 
    vint.value |= (b & 0x7F) << 14;
    if ((b & 0x80) == 0) {
        vint.length = 3;
        return vint;
    }
    b = tvb_get_guint8(tvb, offset+3); 
    vint.value |= (b & 0x7F) << 21;
    if ((b & 0x80) == 0) {
        vint.length = 4;
        return vint;
    }
    b = tvb_get_guint8(tvb, offset+4); 
    // FIXME: need some assertion like assert (b & 0x80) == 0; 
    vint.length = 5;
    vint.value |= ((b & 0x7F) << 28);
    return vint;
}

static vstring_t read_vstring(tvbuff_t *tvb, int offset){
  vstring_t vstring;
  int string_starting_offset;
  int string_length;

  vstring.vint_length = read_vint(tvb, offset);
  string_starting_offset = offset + vstring.vint_length.length;
  string_length = vstring.vint_length.value;

  vstring.value = tvb_get_string_enc(wmem_packet_scope(), tvb, string_starting_offset, string_length, ENC_UTF_8);
  vstring.length = string_length + vstring.vint_length.length;

  return vstring;
}

static void dissect_elasticsearch_zen_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset){
    vint_t version;
    char version_string[9]; /* semantic style versioning 10.99.88 */
    vstring_t cluster_name;
    vstring_t node_name;
    vstring_t node_id;
    vstring_t host_name;
    vstring_t host_address;

	/* Let the user know its a discovery packet */
	col_set_str(pinfo->cinfo, COL_INFO, "Zen Ping: ");


	/* Add the internal header */
	proto_tree_add_item(tree, hf_elasticsearch_internal_header, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

    /* Add the variable length encoded version string */
    version = read_vint(tvb, offset);
    g_snprintf(version_string, sizeof(version_string), "%d.%d.%d", (version.value / 1000000) % 100,
        (version.value / 10000) % 100, (version.value/ 100) % 100);
    proto_tree_add_uint_format_value(tree, hf_elasticsearch_version, tvb, offset, version.length, version.value,
        "%d (%s)" ,version.value, version_string);
    col_append_fstr(pinfo->cinfo, COL_INFO, "v%s", version_string);
    offset += version.length;

    /* Ping request ID */
    proto_tree_add_item(tree, hf_elasticsearch_ping_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Cluster name */
    cluster_name = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_cluster_name, tvb, offset, cluster_name.length, cluster_name.value);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", cluster: %s", cluster_name.value);
    offset += cluster_name.length;

    /* Node name */
    node_name = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_node_name, tvb, offset, node_name.length, node_name.value);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", name: %s", node_name.value);
    offset += node_name.length;

    /* Node ID */
    node_id = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_node_id, tvb, offset, node_id.length, node_id.value);
    offset += node_id.length;

    /* Hostname */
    host_name = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_host_name, tvb, offset, host_name.length, host_name.value);
    offset += host_name.length;

    /* Host address */
    host_address = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_host_address, tvb, offset, host_address.length, host_address.value);
    offset += host_address.length;

	(void)offset;
	(void)tree;
	(void)tvb;
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






