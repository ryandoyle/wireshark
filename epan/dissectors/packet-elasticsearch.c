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

#define ELASTICSEARCH_DISCOVERY_PORT 54328
// ^ wtf the above doesn't work
#define ELASTICSEARCH_INTERNAL_HEADER 0x01090804
#define IPv4_ADDRESS_LENGTH 4

typedef struct {
    int length;
    int value;
} vint_t;

typedef struct {
    vint_t vint_length;
    int length; 
    char *value;
} vstring_t;

typedef struct {
    int length;
    int value;
    char string[9];
} version_t;

static int proto_elasticsearch = -1;

/* Fields */
static int hf_elasticsearch_internal_header = -1;
static int hf_elasticsearch_version = -1;
static int hf_elasticsearch_ping_request_id = -1;
static int hf_elasticsearch_cluster_name= -1;
static int hf_elasticsearch_node_name = -1;
static int hf_elasticsearch_node_id = -1;
static int hf_elasticsearch_host_name = -1;
static int hf_elasticsearch_host_address = -1;
static int hf_elasticsearch_address_type = -1;
static int hf_elasticsearch_address_format = -1;
static int hf_elasticsearch_address_name = -1;
static int hf_elasticsearch_address_length = -1;
static int hf_elasticsearch_address_ipv4 = -1;
static int hf_elasticsearch_address_ipv6 = -1;
static int hf_elasticsearch_address_ipv6_scope_id = -1;
static int hf_elasticsearch_attributes_length = -1;
static int hf_elasticsearch_address_port = -1;

/* Trees */
static gint ett_elasticsearch = -1;
static gint ett_elasticsearch_address = -1;
static gint ett_elasticsearch_discovery_node = -1;


static const value_string address_types[] = {
    { 0x0, "Dummy" },
    { 0x1, "Inet Socket" },
    { 0x2, "Local" },
};

static const value_string address_format[] = {
#define ADDRESS_FORMAT_NUEMRIC 0x0
    { 0x0, "Numeric" },
#define ADDRESS_FORMAT_STRING 0x1
    { 0x1, "String" },
};


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
          { "Host address", "elasticsearch.host_address",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_type,
          { "Type", "elasticsearch.address.type",
            FT_UINT16, BASE_DEC,
            VALS(address_types), 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_format,
          { "Format", "elasticsearch.address.format",
            FT_UINT8, BASE_DEC,
            VALS(address_format), 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_name,
          { "Name", "elasticsearch.address.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_length,
          { "Length", "elasticsearch.address.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_ipv4,
          { "IP", "elasticsearch.address.ipv4",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_ipv6,
          { "IP", "elasticsearch.address.ipv6",
            FT_IPv6, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_ipv6_scope_id,
          { "IP", "elasticsearch.address.ipv6.scope_id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_address_port,
          { "Port", "elasticsearch.address.port",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_elasticsearch_attributes_length,
          { "Attributes length", "elasticsearch.attributes.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },

    };

	static gint *ett[] = {
			&ett_elasticsearch,
			&ett_elasticsearch_address,
			&ett_elasticsearch_discovery_node,
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

static int partial_dissect_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset){
    proto_tree *address_tree;
    proto_item *address_item;
    int start_offset;
    guint8 es_address_format;
    guint8 address_length;
    vstring_t address_name;

    /* Store this away for later */
    start_offset = offset;

    /* Address tree */
    address_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_elasticsearch_address, &address_item, "Address" );

    /* Address type */
    proto_tree_add_item(address_tree, hf_elasticsearch_address_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* ^  FIXME maybe ? - It is possible that there are different address types but these will never be different on the wire */

    /* Address format */
    es_address_format = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(address_tree, hf_elasticsearch_address_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (es_address_format == ADDRESS_FORMAT_NUEMRIC){
      address_length = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(address_tree, hf_elasticsearch_address_length, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      /* Its either IPv4 or IPv6 depending on the length */
      if(address_length == IPv4_ADDRESS_LENGTH){
        proto_tree_add_item(address_tree, hf_elasticsearch_address_ipv4, tvb, offset, 4, ENC_NA);
        offset += 4;
      }
      else {
        proto_tree_add_item(address_tree, hf_elasticsearch_address_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(address_tree, hf_elasticsearch_address_ipv6_scope_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    }
    else if (es_address_format == ADDRESS_FORMAT_STRING){
        address_name = read_vstring(tvb, offset);
        proto_tree_add_string(address_tree, hf_elasticsearch_address_name, tvb, offset, address_name.length, address_name.value);
        offset += address_name.length;
    }
    else{
        /* FIXME: shouldn't get here, invalid format type */
    }

    proto_tree_add_item(address_item, hf_elasticsearch_address_port, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Fix up the length of the subtree */
    proto_item_set_len(address_item, offset - start_offset);

	(void)offset;
	(void)tree;
	(void)tvb;
    (void)pinfo;

    return offset;
    

}

static version_t parse_elasticsearch_version(tvbuff_t *tvb, int offset){
    version_t version;
    vint_t raw_version_value;

    raw_version_value = read_vint(tvb, offset);
    version.length = raw_version_value.length;
    version.value = raw_version_value.value;
    g_snprintf(version.string, sizeof(version.string), "%d.%d.%d", (version.value / 1000000) % 100,
            (version.value / 10000) % 100, (version.value/ 100) % 100);

    return version;
}

static void dissect_elasticsearch_zen_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset){
    version_t version;
    vstring_t cluster_name;
    vstring_t node_name;
    vstring_t node_id;
    vstring_t host_name;
    vstring_t host_address;
    vint_t attributes_length;
    version_t node_version;
    proto_tree *discovery_node_tree;
    proto_item *discovery_node_item;

	/* Let the user know its a discovery packet */
	col_set_str(pinfo->cinfo, COL_INFO, "Zen Ping: ");


	/* Add the internal header */
	proto_tree_add_item(tree, hf_elasticsearch_internal_header, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

    /* Add the variable length encoded version string */
    version = parse_elasticsearch_version(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_elasticsearch_version, tvb, offset, version.length, version.value,
        "%d (%s)" ,version.value, version.string);
    col_append_fstr(pinfo->cinfo, COL_INFO, "v%s", version.string);
    offset += version.length;

    /* Ping request ID */
    proto_tree_add_item(tree, hf_elasticsearch_ping_request_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Cluster name */
    cluster_name = read_vstring(tvb, offset);
    proto_tree_add_string(tree, hf_elasticsearch_cluster_name, tvb, offset, cluster_name.length, cluster_name.value);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", cluster: %s", cluster_name.value);
    offset += cluster_name.length;


    /* Discovery node tree */
    discovery_node_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_elasticsearch_discovery_node, &discovery_node_item, "Node" );

    /* Node name */
    node_name = read_vstring(tvb, offset);
    proto_tree_add_string(discovery_node_tree, hf_elasticsearch_node_name, tvb, offset, node_name.length, node_name.value);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", name: %s", node_name.value);
    offset += node_name.length;

    /* Node ID */
    node_id = read_vstring(tvb, offset);
    proto_tree_add_string(discovery_node_tree, hf_elasticsearch_node_id, tvb, offset, node_id.length, node_id.value);
    offset += node_id.length;

    /* Hostname */
    host_name = read_vstring(tvb, offset);
    proto_tree_add_string(discovery_node_tree, hf_elasticsearch_host_name, tvb, offset, host_name.length, host_name.value);
    offset += host_name.length;

    /* Host address */
    host_address = read_vstring(tvb, offset);
    proto_tree_add_string(discovery_node_tree, hf_elasticsearch_host_address, tvb, offset, host_address.length, host_address.value);
    offset += host_address.length;

    /* Address */
    offset = partial_dissect_address(tvb, pinfo, discovery_node_tree, offset);

    /* Attributes. These are zero for discovery packets */
    attributes_length = read_vint(tvb, offset);
    proto_tree_add_uint(discovery_node_tree, hf_elasticsearch_attributes_length, tvb, offset, attributes_length.length, attributes_length.value);
    offset += attributes_length.length;

    /* Version again */
    node_version = parse_elasticsearch_version(tvb, offset);
    proto_tree_add_uint_format_value(discovery_node_tree, hf_elasticsearch_version, tvb, offset, node_version.length, node_version.value,
            "%d (%s)" ,node_version.value, node_version.string);
    offset += node_version.length;

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
	dissector_add_uint("udp.port", ELASTICSEARCH_DISCOVERY_PORT, elasticsearch_handle); // FIXME: Use the #define macro for the port

}






