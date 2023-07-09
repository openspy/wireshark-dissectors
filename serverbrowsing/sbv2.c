#include "serverbrowsing.h"

#define FIXED_HEADER_LEN 6
#define ENCTYPEX_DATA_LEN 261

int proto_sbv2 = -1;
gint proto_sbv2_ett = -1;

static gint* sbv2_etts[] = {
    &proto_sbv2_ett
};

int sbv2_incoming_length = -1;
int sbv2_request_type = -1;
int sbv2_request_name = -1;
int sbv2_listreq_protocol_version = -1;
int sbv2_listreq_encoding_version = -1;
int sbv2_listreq_game_version = -1;
int sbv2_listreq_for_gamename = -1;
int sbv2_listreq_from_gamename = -1;
int sbv2_listreq_challenge = -1;
int sbv2_listreq_filter = -1;
int sbv2_listreq_key_list = -1;
int sbv2_listreq_options = -1;
int sbv2_listreq_source_ip = -1;
int sbv2_listreq_max_results = -1;

int sbv2_listreq_options_send_fields_for_all = -1;
int sbv2_listreq_options_no_server_list = -1;
int sbv2_listreq_options_push_updates = -1;
int sbv2_listreq_options_send_groups = -1;
int sbv2_listreq_options_no_list_cache = -1;
int sbv2_listreq_options_limit_result_count = -1;

int sbv2_crypt_header_len = -1;
int sbv2_crypt_header_random_data = -1;
int sbv2_crypt_header_keylen = -1;
int sbv2_crypt_header_key_data = -1;

int sbv2_listresp_public_ip = -1;
int sbv2_listresp_query_port = -1;
int sbv2_listresp_num_fields = -1;
int sbv2_listresp_field_type = -1;
int sbv2_listresp_field_name = -1;
int sbv2_listresp_num_popular_values = -1;
int sbv2_listresp_popular_value = -1;

int sbv2_listresp_server_flags = -1;
int sbv2_listresp_server_ip = -1;
int sbv2_listresp_server_group_number = -1;
int sbv2_listresp_server_port = -1;
int sbv2_listresp_server_private_ip = -1;
int sbv2_listresp_server_private_port = -1;
int sbv2_listresp_server_icmp_ip = -1;
int sbv2_listresp_server_updateflags_unsolicited_udp_flag = -1;
int sbv2_listresp_server_updateflags_private_ip_flag = -1;
int sbv2_listresp_server_updateflags_connect_negotiate_flag = -1;
int sbv2_listresp_server_updateflags_icmp_ip_flag = -1;
int sbv2_listresp_server_updateflags_nonstandard_port_flag = -1;
int sbv2_listresp_server_updateflags_nonstandard_private_port_flag = -1;
int sbv2_listresp_server_updateflags_has_keys_flag = -1;
int sbv2_listresp_server_updateflags_has_fullkeys_flag = -1;
int sbv2_listresp_server_field_strindex = -1;
int sbv2_listresp_server_field_keytype = -1;
int sbv2_listresp_server_field_keyname = -1;
int sbv2_listresp_server_field_keyvalue = -1;

static int* const server_updateflags_bits[] = {
	&sbv2_listresp_server_updateflags_unsolicited_udp_flag,
	&sbv2_listresp_server_updateflags_private_ip_flag,
	&sbv2_listresp_server_updateflags_connect_negotiate_flag,
	&sbv2_listresp_server_updateflags_icmp_ip_flag,
	&sbv2_listresp_server_updateflags_nonstandard_port_flag,
	&sbv2_listresp_server_updateflags_nonstandard_private_port_flag,
	&sbv2_listresp_server_updateflags_has_keys_flag,
	&sbv2_listresp_server_updateflags_has_fullkeys_flag,
	NULL
};

static int* const listreq_options_bits[] = {
	&sbv2_listreq_options_send_fields_for_all,
	&sbv2_listreq_options_no_server_list,
	&sbv2_listreq_options_push_updates,
	&sbv2_listreq_options_send_groups,
	&sbv2_listreq_options_no_list_cache,
	&sbv2_listreq_options_limit_result_count,
	NULL
};


static hf_register_info sbv2_fields_hf[] = {
    //crypt command properties
    { &sbv2_incoming_length,
        { "incoming_length", "sbv2.incoming_length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_request_type,
        { "request_type", "sbv2.request_type",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_request_name,
        { "request_name", "sbv2.request_name",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_protocol_version,
        { "protocol_version", "sbv2.listreq.protocol_version",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_encoding_version,
        { "encoding_version", "sbv2.listreq.encoding_version",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_game_version,
        { "game_version", "sbv2.listreq.game_version",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_for_gamename,
        { "for_gamename", "sbv2.listreq.for_gamename",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_from_gamename,
        { "from_gamename", "sbv2.listreq.from_gamename",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_challenge,
        { "challenge", "sbv2.listreq.challenge",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_filter,
        { "filter", "sbv2.listreq.filter",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_key_list,
        { "key_list", "sbv2.listreq.key_list",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_options,
        { "options", "sbv2.listreq.options",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_send_fields_for_all,
        { "send_fields_for_all", "sbv2.listreq.options.send_fields_for_all",
        FT_BOOLEAN, 8,
        NULL, SEND_FIELDS_FOR_ALL,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_no_server_list,
        { "no_server_list", "sbv2.listreq.options.no_server_list",
        FT_BOOLEAN, 8,
        NULL, NO_SERVER_LIST,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_push_updates,
        { "push_updates", "sbv2.listreq.options.push_updates",
        FT_BOOLEAN, 8,
        NULL, PUSH_UPDATES,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_send_groups,
        { "send_groups", "sbv2.listreq.options.send_groups",
        FT_BOOLEAN, 8,
        NULL, SEND_GROUPS,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_no_list_cache,
        { "no_list_cache", "sbv2.listreq.options.no_list_cache",
        FT_BOOLEAN, 8,
        NULL, NO_LIST_CACHE,
        NULL, HFILL }
    },
    { &sbv2_listreq_options_limit_result_count,
        { "limit_result_count", "sbv2.listreq.options.limit_result_count",
        FT_BOOLEAN, 8,
        NULL, LIMIT_RESULT_COUNT,
        NULL, HFILL }
    },
    { &sbv2_listreq_source_ip,
        { "alternate_source_ip", "sbv2.listreq.alternate_source_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listreq_max_results,
        { "max_results", "sbv2.listreq.max_results",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },

    //list response
    { &sbv2_listresp_public_ip,
        { "public_ip", "sbv2.listresp.public_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_query_port,
        { "query_port", "sbv2.listresp.query_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_num_fields,
        { "num_fields", "sbv2.listresp.num_fields",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_field_type,
        { "field_type", "sbv2.listresp.field_type",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_field_name,
        { "field_name", "sbv2.listresp.field_name",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_num_popular_values,
        { "num_popular_values", "sbv2.listresp.num_popular_values",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_popular_value,
        { "popular_value", "sbv2.listresp.popular_value",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    //server item
    { &sbv2_listresp_server_flags,
        { "server_flags", "sbv2.listresp.server_flags",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_ip,
        { "server_ip", "sbv2.listresp.server_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_group_number,
        { "group_number", "sbv2.listresp.group_number",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_port,
        { "server_port", "sbv2.listresp.server_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_private_ip,
        { "private_ip", "sbv2.listresp.private_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_private_port,
        { "private_port", "sbv2.listresp.private_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_icmp_ip,
        { "icmp_ip", "sbv2.listresp.icmp_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_field_strindex,
        { "field.strindex", "sbv2.listresp.field.strindex",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_field_keytype,
        { "field.keytype", "sbv2.listresp.field.keytype",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_field_keyname,
        { "field.keyname", "sbv2.listresp.field.keyname",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_field_keyvalue,
        { "field.keyvalue", "sbv2.listresp.field.keyvalue",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },

    // server list item flags
    { &sbv2_listresp_server_updateflags_unsolicited_udp_flag,
        { "unsolicited_udp_flag", "sbv2.listresp.server_flags.unsolicited_udp_flag",
        FT_BOOLEAN, 9,
        NULL, UNSOLICITED_UDP_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_private_ip_flag,
        { "private_ip_flag", "sbv2.listresp.server_flags.private_ip_flag",
        FT_BOOLEAN, 9,
        NULL, PRIVATE_IP_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_connect_negotiate_flag,
        { "connect_negotiate_flag", "sbv2.listresp.server_flags.connect_negotiate_flag",
        FT_BOOLEAN, 9,
        NULL, CONNECT_NEGOTIATE_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_icmp_ip_flag,
        { "icmp_ip_flag", "sbv2.listresp.server_flags.icmp_ip_flag",
        FT_BOOLEAN, 9,
        NULL, ICMP_IP_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_nonstandard_port_flag,
        { "nonstandard_port_flag", "sbv2.listresp.server_flags.nonstandard_port_flag",
        FT_BOOLEAN, 9,
        NULL, NONSTANDARD_PORT_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_nonstandard_private_port_flag,
        { "nonstandard_private_port_flag", "sbv2.listresp.server_flags.nonstandard_private_port_flag",
        FT_BOOLEAN, 9,
        NULL, NONSTANDARD_PRIVATE_PORT_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_has_keys_flag,
        { "has_keys_flag", "sbv2.listresp.server_flags.has_keys_flag",
        FT_BOOLEAN, 9,
        NULL, HAS_KEYS_FLAG,
        NULL, HFILL }
    },
    { &sbv2_listresp_server_updateflags_has_fullkeys_flag,
        { "has_fullkeys_flag", "sbv2.listresp.server_flags.has_fullkeys_flag",
        FT_BOOLEAN, 9,
        NULL, HAS_FULL_RULES_FLAG,
        NULL, HFILL }
    },
    //
    { &sbv2_crypt_header_len,
        { "crypt.len", "sbv2.listresp.crypt.len",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_crypt_header_random_data,
        { "crypt.random", "sbv2.crypt.random",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &sbv2_crypt_header_keylen,
        { "crypt.keylen", "sbv2.listresp.crypt.keylen",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_crypt_header_key_data,
        { "crypt.key", "sbv2.crypt.key",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
};

typedef struct _sbv2_conv_t {
    char enctypex_data[ENCTYPEX_DATA_LEN];
    char challenge[LIST_CHALLENGE_LEN];
    int list_req_options;
    int response_server_list_end_pdu;
    const char** query_from_game; //pointer to gslist_keys
} sbv2_conv_t;

typedef struct _sbv2_pdu_crypto_state {
	guchar *decrypted_buffer;
	tvbuff_t *decrypted_tvb;
    int len;
} sbv2_pdu_crypto_state;

typedef struct {
    uint8_t field_type;
    const char *field_name;
} FieldInfo;

static sbv2_conv_t* get_sbv2_conversation_data(packet_info* pinfo)
{
    conversation_t* conversation;
    sbv2_conv_t* conv_data;

    conversation = find_or_create_conversation(pinfo);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (sbv2_conv_t*)conversation_get_proto_data(conversation, proto_sbv2);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = (sbv2_conv_t*)wmem_alloc0(wmem_file_scope(), sizeof(sbv2_conv_t));

        conversation_add_proto_data(conversation, proto_sbv2,
            conv_data);
    }

    return conv_data;
}

static sbv2_pdu_crypto_state* get_sbv2_pdu_crypto_state(packet_info* pinfo) {
    conversation_t* conversation;
    sbv2_pdu_crypto_state* conv_data;

    conversation = find_or_create_conversation_by_id(pinfo, CONVERSATION_TCP, pinfo->num);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (sbv2_pdu_crypto_state*)conversation_get_proto_data(conversation, proto_sbv2);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = (sbv2_pdu_crypto_state*)wmem_alloc0(wmem_file_scope(), sizeof(sbv2_pdu_crypto_state));

        //copy latest crypto state
        sbv2_conv_t* sbv2_conv = get_sbv2_conversation_data(pinfo);

        //memcpy(&conv_data->crypto_state, &sbv2_conv->enctypex_data, sizeof(conv_data->crypto_state));

        conversation_add_proto_data(conversation, proto_sbv2,
            conv_data);
    }

    return conv_data;
}


int dissect_sbv2_list_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2 List Req");
    proto_tree_add_item(tree, sbv2_listreq_protocol_version, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, sbv2_listreq_encoding_version, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, sbv2_listreq_game_version, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);

    offset += add_string_nts_item(tvb, tree, sbv2_listreq_for_gamename, offset);
    
    int from_len = add_string_nts_item(tvb, tree, sbv2_listreq_from_gamename, offset);
    char *from_gamename = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, from_len, ENC_ASCII);
    if(conv->query_from_game == NULL) {
        conv->query_from_game = gslist_keys_find_by_gamename(from_gamename, from_len);
    }

    offset += from_len;

    proto_tree_add_item(tree, sbv2_listreq_challenge, tvb, offset,  LIST_CHALLENGE_LEN, ENC_BIG_ENDIAN); 
    for(int i=0;i<LIST_CHALLENGE_LEN;i++) {
        conv->challenge[i] = tvb_get_guint8(tvb, offset++);
    }
    offset += add_string_nts_item(tvb, tree, sbv2_listreq_filter, offset);
    offset += add_string_nts_item(tvb, tree, sbv2_listreq_key_list, offset);

    guint32 options = tvb_get_ntohl(tvb, offset);
    conv->list_req_options = options;
    proto_tree_add_bitmask_value(tree, tvb, offset, sbv2_listreq_options, proto_sbv2_ett, listreq_options_bits, options); offset += sizeof(uint32_t);

    if(options & ALTERNATE_SOURCE_IP) {
        proto_tree_add_item(tree, sbv2_listreq_source_ip, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    }
    if (options & LIMIT_RESULT_COUNT) {
        proto_tree_add_item(tree, sbv2_listreq_max_results, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    }

    return tvb_captured_length(tvb);
}

int dissect_sbv2_client_stream(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    
    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2");
    guint32 request_type = 0;
    proto_tree_add_item(tree, sbv2_incoming_length, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);
    proto_tree_add_item_ret_uint(tree, sbv2_request_type, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN, &request_type); offset += sizeof(uint8_t);
    switch(request_type) {
        case SERVER_LIST_REQUEST:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "SERVER_LIST_REQUEST");
            return dissect_sbv2_list_request(tvb, pinfo, tree, data, offset);
        case SERVER_INFO_REQUEST:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "SERVER_INFO_REQUEST");
        break;
        case SEND_MESSAGE_REQUEST:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "SEND_MESSAGE_REQUEST");
        break;
        case KEEPALIVE_REPLY:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "KEEPALIVE_REPLY");
        break;
        case MAPLOOP_REQUEST:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "MAPLOOP_REQUEST");
        break;
        case PLAYERSEARCH_REQUEST:
            proto_tree_add_string(tree, sbv2_request_name, tvb, offset - 1, sizeof(uint8_t), "PLAYERSEARCH_REQUEST");
        break;

    }
    return tvb_captured_length(tvb);
}

static guint
    get_sbv2_incoming_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
    uint16_t message_length = tvb_get_ntohs(tvb, offset);
    return (guint)message_length;
}

static int ServerSizeForFlags(int flags)
{
	int size = 5; //all servers are at least 5 ..
	if (flags & PRIVATE_IP_FLAG)
		size += 4;
	if (flags & ICMP_IP_FLAG)
		size += 4;
	if (flags & NONSTANDARD_PORT_FLAG)
		size += 2;
	if (flags & NONSTANDARD_PRIVATE_PORT_FLAG)
		size += 2;
	return size;

}

static guint
    get_sbv2_response_crypt_random_len(packet_info* pinfo _U_, tvbuff_t* tvb, int original_offset, void* data _U_)
{
    int offset = original_offset;
    gint available = tvb_reported_length_remaining(tvb, offset);

    //calculate crypt header stuff
    guint8 random_len = tvb_get_guint8(tvb, offset); offset++;
    random_len ^= 0xEC;

    available--;
    if(available < random_len) {
        pinfo->desegment_offset = original_offset;
        pinfo->desegment_len = random_len;
        return 0;
    }
    available -= random_len;
    offset += random_len;

    guint8 key_len = tvb_get_guint8(tvb, offset); offset++;
    key_len ^= 0xEA; 
    available--;

    if(available < key_len) {
        pinfo->desegment_offset = original_offset;
        pinfo->desegment_len = key_len;
        return 0;
    }
    available -= key_len;
    offset += key_len;


    //decrypt data...
    char ctx[ENCTYPEX_DATA_LEN];
    memset(&ctx, 0, sizeof(ctx));

    sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);
    if(conv->query_from_game == NULL) { //XXX:: handle this better?
        return 0;
    }
    


    int enctypex_data_len = offset - original_offset;
    void *key_data = tvb_memdup(wmem_packet_scope(), tvb, original_offset, enctypex_data_len);
    
    enctypex_init(&ctx, conv->query_from_game[2], conv->challenge, key_data, &enctypex_data_len, NULL);
    memcpy(&conv->enctypex_data, &ctx, sizeof(ctx));

    guchar* decrypted_buffer = (guchar*)tvb_memdup(wmem_packet_scope(), tvb, offset, available);
    enctypex_func6(&ctx, decrypted_buffer, available);

    tvbuff_t* decrypted_tvb = tvb_new_real_data(decrypted_buffer, available, available);
    int dec_offset = 0;

    //calculate fixed header
    if(available < FIXED_HEADER_LEN) { 
        pinfo->desegment_offset = original_offset;
        pinfo->desegment_len = FIXED_HEADER_LEN;
        tvb_free(decrypted_tvb);
        return 0;
    }


    //skip fixed header
    dec_offset += FIXED_HEADER_LEN;
    available -= FIXED_HEADER_LEN;


    if(available < 1) { 
        pinfo->desegment_offset = original_offset;
        pinfo->desegment_len = 1;
        tvb_free(decrypted_tvb);
        return 0;
    }

    //calculate key list
    guint8 key_list_size = tvb_get_guint8(decrypted_tvb, dec_offset++);
    available--;
    for(int i=0;i<key_list_size;i++) {
        
        guint8 key_type = tvb_get_guint8(decrypted_tvb, dec_offset++); available--;
        int str_remaining = tvb_reported_length_remaining(decrypted_tvb, dec_offset);
        gint len = tvb_strnlen(decrypted_tvb, dec_offset, str_remaining);
        if(len == -1) {
            pinfo->desegment_offset = original_offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            tvb_free(decrypted_tvb);
            return 0;
        }
        dec_offset += len + 1;
        available -= len + 1;
    }

    if(available < 1) { 
        pinfo->desegment_offset = original_offset;
        pinfo->desegment_len = 1;
        return 0;
    }
    //calculate unique list
    guint8 unique_list_size = tvb_get_guint8(decrypted_tvb, dec_offset++);
    available --;

    for(int i=0;i<unique_list_size;i++) {
        int str_remaining = tvb_reported_length_remaining(decrypted_tvb, dec_offset);
        gint str_len = tvb_strnlen(decrypted_tvb, dec_offset, str_remaining);
        if(str_len == -1) {
            pinfo->desegment_offset = original_offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            tvb_free(decrypted_tvb);
            return 0;
        }
        dec_offset += str_len + 1;
        available -= str_len + 1;
    }

    //calculate main server list


    while(1) {
        if(available < 5) {
            pinfo->desegment_offset = original_offset;
            pinfo->desegment_len = 5;
            tvb_free(decrypted_tvb);
            return 0;
        }
        
        guint8 flags = tvb_get_guint8(decrypted_tvb, dec_offset++);
        available--;
        int expected_size = ServerSizeForFlags(flags) - 1;
        if(available < expected_size) { 
            pinfo->desegment_offset = original_offset;
            pinfo->desegment_len = expected_size;
            tvb_free(decrypted_tvb);
            return 0;
        }

        guint32 ip = tvb_get_ntohl(decrypted_tvb, dec_offset);
        dec_offset += expected_size;
        available -= expected_size;
        if(ip == 0xFFFFFFFF) {
            break;            
        }

        if(flags & HAS_KEYS_FLAG) {
            for(int i=0;i<key_list_size;i++) {
                guint8 string_index = tvb_get_guint8(decrypted_tvb, dec_offset++); available--;
                int str_remaining = tvb_reported_length_remaining(decrypted_tvb, dec_offset);
                gint len = tvb_strnlen(decrypted_tvb, dec_offset, str_remaining);
                if(len == -1) {
                    pinfo->desegment_offset = original_offset;
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    tvb_free(decrypted_tvb);
                    return 0;
                }
                dec_offset += len + 1;
                available -= len+ 1;
            }
        }

    }

    //now that len is known... decrypt only the list response data
    tvb_free(decrypted_tvb);

    decrypted_buffer = (guchar*)tvb_memdup(wmem_file_scope(), tvb, offset, dec_offset);
    enctypex_func6(&conv->enctypex_data, decrypted_buffer, dec_offset);

    decrypted_tvb = tvb_new_real_data(decrypted_buffer, dec_offset, dec_offset);

    sbv2_pdu_crypto_state *pdu_state = get_sbv2_pdu_crypto_state(pinfo);
    pdu_state->decrypted_tvb = decrypted_tvb;
    pdu_state->len = dec_offset;

    //after here is only adhoc messages!
    return (guint)offset + dec_offset;
}

int dissect_sbv2_response_list_item(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset, guint32 num_keys, FieldInfo *fields) {
    sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);

    proto_item* ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
    proto_tree* subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
    proto_item_set_text(subtree, "Server Item");
    tree = subtree;
    
    int len = 0;
    guint8 flags = tvb_get_guint8(tvb, offset);
    gint32 ip = 0;
	proto_tree_add_bitmask_value(tree, tvb, len + offset, sbv2_listresp_server_flags, proto_sbv2_ett, server_updateflags_bits, flags); len += sizeof(uint8_t);

    ip = tvb_get_ntohl(tvb, offset + len);

    if(conv->list_req_options & SEND_GROUPS) {
        proto_tree_add_item(tree, sbv2_listresp_server_group_number, tvb, len + offset, sizeof(uint32_t), ENC_BIG_ENDIAN); len += sizeof(uint32_t);
    } else {
        proto_tree_add_item(tree, sbv2_listresp_server_ip, tvb, len + offset, sizeof(uint32_t), ENC_BIG_ENDIAN); len += sizeof(uint32_t);
    }
    

    if(ip == -1) {
        return -len;
    }
    if (flags & NONSTANDARD_PORT_FLAG) {
        proto_tree_add_item(tree, sbv2_listresp_server_port, tvb, len + offset, sizeof(uint16_t), ENC_BIG_ENDIAN); len += sizeof(uint16_t);
    }
    if (flags & PRIVATE_IP_FLAG) {
        proto_tree_add_item(tree, sbv2_listresp_server_private_ip, tvb, len + offset, sizeof(uint32_t), ENC_BIG_ENDIAN); len += sizeof(uint32_t);
    }
    if (flags & NONSTANDARD_PRIVATE_PORT_FLAG) {
        proto_tree_add_item(tree, sbv2_listresp_server_private_port, tvb, len + offset, sizeof(uint16_t), ENC_BIG_ENDIAN); len += sizeof(uint16_t);    
    }
    if(flags & ICMP_IP_FLAG) {
        proto_tree_add_item(tree, sbv2_listresp_server_icmp_ip, tvb, len + offset, sizeof(uint32_t), ENC_BIG_ENDIAN); len += sizeof(uint32_t);
    }
    

    if(flags & HAS_KEYS_FLAG) {

        proto_item* ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
        proto_tree* subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
        proto_item_set_text(subtree, "Keys");
    
        for(int i=0;i<num_keys;i++) {
            proto_item* key_ti = proto_tree_add_item(subtree, proto_sbv2, tvb, 0, -1, ENC_NA);
            proto_tree* key_subtree = proto_item_add_subtree(key_ti, proto_sbv2_ett);
            proto_item_set_text(key_subtree, fields[i].field_name);
            proto_tree_add_item(key_subtree, sbv2_listresp_server_field_strindex, tvb, len + offset, sizeof(uint8_t), ENC_BIG_ENDIAN); len += sizeof(uint8_t);
            int str_remaining = tvb_reported_length_remaining(tvb, len + offset);
            gint str_len = tvb_strnlen(tvb, len + offset, str_remaining);
            //sbv2_listresp_server_field_keyname
            proto_tree_add_uint(key_subtree, sbv2_listresp_server_field_keytype, tvb, len + offset, str_len + 1, fields[i].field_type);
            proto_tree_add_string(key_subtree, sbv2_listresp_server_field_keyname, tvb, len + offset, str_len + 1, fields[i].field_name);
            proto_tree_add_item(key_subtree, sbv2_listresp_server_field_keyvalue, tvb, len + offset, str_len + 1, ENC_BIG_ENDIAN); len += str_len + 1;
        }
    }
    return len;
}

int dissect_sbv2_response_list_header(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);
    conv->response_server_list_end_pdu = pinfo->num;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2 list response");

    proto_tree_add_item(tree, sbv2_listresp_public_ip, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    proto_tree_add_item(tree, sbv2_listresp_query_port, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);

    guint32 num_keys;
    proto_tree_add_item_ret_uint(tree, sbv2_listresp_num_fields, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN, &num_keys); offset += sizeof(uint8_t);

    proto_item* ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
    proto_tree* subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
    proto_item_set_text(subtree, "Fields");


    
    FieldInfo *fields = (FieldInfo *)wmem_alloc0(pinfo->pool, sizeof(FieldInfo) * num_keys);

    for(int i=0;i<num_keys;i++) {
        guint32 field_type;
        proto_tree_add_item_ret_uint(subtree, sbv2_listresp_field_type, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN, &field_type); offset += sizeof(uint8_t);
        int str_remaining = tvb_reported_length_remaining(tvb, offset);
        gint str_len = tvb_strnlen(tvb, offset, str_remaining);
        guint8 *string = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_ASCII);
        fields[i].field_type = field_type;
        fields[i].field_name = (const char *)string;
        proto_tree_add_item(subtree, sbv2_listresp_field_name, tvb, offset, str_len + 1, ENC_BIG_ENDIAN); offset += str_len + 1;
    }

    guint32 num_popular_keys;
    proto_tree_add_item_ret_uint(tree, sbv2_listresp_num_popular_values, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN, &num_popular_keys); offset += sizeof(uint8_t);

    

    ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
    proto_item_set_text(subtree, "Popular Values");

    for(int i=0;i<num_popular_keys;i++) {
        int str_remaining = tvb_reported_length_remaining(tvb, offset);
        gint str_len = tvb_strnlen(tvb, offset, str_remaining);

        proto_tree_add_item(subtree, sbv2_listresp_popular_value, tvb, offset, str_len + 1, ENC_BIG_ENDIAN); offset += str_len + 1;
    }


    while(true) {
        int len = dissect_sbv2_response_list_item(tvb, pinfo, tree, data, offset, num_keys, fields);
        if(len < 0) {
            offset += -len;
            break;
        }
        offset += len;
    }
    
    return tvb_captured_length(tvb);
}


int dissect_sbv2_response_crypt_header(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    int offset = 0;

    sbv2_pdu_crypto_state *pdu_state = get_sbv2_pdu_crypto_state(pinfo);



    guint8 len = tvb_get_guint8(tvb, offset);
    len ^= 0xEC;
    proto_tree_add_uint(tree, sbv2_crypt_header_len, tvb, offset, sizeof(uint8_t), len); offset++;
    proto_tree_add_item(tree, sbv2_crypt_header_random_data, tvb, offset,  len, ENC_BIG_ENDIAN); offset += len;
    

    len = tvb_get_guint8(tvb, offset);
    len ^= 0xEA;

    proto_tree_add_uint(tree, sbv2_crypt_header_keylen, tvb, offset, sizeof(uint8_t), len); offset++;
    proto_tree_add_item(tree, sbv2_crypt_header_key_data, tvb, offset, len, ENC_BIG_ENDIAN); offset += len;

    tvb = pdu_state->decrypted_tvb;
    offset = 0;

    add_new_data_source(pinfo, tvb, "Decrypted Data");

    proto_item* ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
    proto_tree* subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
    proto_item_set_text(subtree, "List Response");

    return dissect_sbv2_response_list_header(tvb, pinfo, subtree, data, offset);
}

int dissect_sbv2_response_adhoc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2 Adhoc");

    proto_item* ti = proto_tree_add_item(tree, proto_sbv2, tvb, 0, -1, ENC_NA);
    proto_tree* subtree = proto_item_add_subtree(ti, proto_sbv2_ett);
    proto_item_set_text(subtree, "Adhoc Message");
    tree = subtree;
    
    int offset = 0;
    guint type;
    guint len = 0;
    //proto_tree_add_item_ret_uint(tree, sbv2_incoming_length, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN, &len); offset += sizeof(uint16_t); len -= 2;

    //proto_tree_add_item(tree, sbv2_listreq_challenge, tvb, offset,  len, ENC_BIG_ENDIAN); offset += len;

    proto_tree_add_item_ret_uint(tree, sbv2_incoming_length, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN, &len); offset += sizeof(uint16_t);
    proto_tree_add_item_ret_uint(tree, sbv2_request_type, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN, &type); offset += sizeof(uint8_t);

    len -= offset;


    proto_tree_add_item(tree, sbv2_listreq_challenge, tvb, offset,  len, ENC_BIG_ENDIAN); offset += len;

    switch(type) {

    }

    return tvb_captured_length(tvb);
}

int dissect_sbv2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) { 

    if(pinfo->srcport != DEFAULT_SBV2_PORT) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_sbv2_incoming_message_len, dissect_sbv2_client_stream, data);
    } else {
        sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);
        if(pinfo->num <= conv->response_server_list_end_pdu || conv->response_server_list_end_pdu == 0) {
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_sbv2_response_crypt_random_len, dissect_sbv2_response_crypt_header, data);
        } else {
            sbv2_pdu_crypto_state *pdu_state = get_sbv2_pdu_crypto_state(pinfo);

            if(conv->query_from_game == NULL) {
                return 0;
            }

            if(pdu_state->decrypted_tvb != NULL) {
                add_new_data_source(pinfo, pdu_state->decrypted_tvb, "Decrypted Data");

                tcp_dissect_pdus(pdu_state->decrypted_tvb, pinfo, tree, TRUE, 2, get_sbv2_incoming_message_len, dissect_sbv2_response_adhoc, data);
            } else {
                int available = tvb_reported_length_remaining(tvb, 0);

                char enctypex_data[ENCTYPEX_DATA_LEN];
                memcpy(&enctypex_data, &conv->enctypex_data, sizeof(enctypex_data));

                guchar* decrypted_buffer = (guchar*)tvb_memdup(wmem_file_scope(), tvb, 0, available);

                enctypex_func6(&enctypex_data, decrypted_buffer, available);

                tvbuff_t* decrypted_tvb = tvb_new_real_data(decrypted_buffer, available, available);

                add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");

                tcp_dissect_pdus(decrypted_tvb, pinfo, tree, TRUE, 2, get_sbv2_incoming_message_len, dissect_sbv2_response_adhoc, data);

                memcpy(&conv->enctypex_data, &enctypex_data, sizeof(enctypex_data));

                pdu_state->decrypted_buffer = decrypted_buffer;
                pdu_state->decrypted_tvb = decrypted_tvb;
                pdu_state->len = available;
            }

        }        
    }   
    return tvb_captured_length(tvb);
}



void proto_register_sbv2(void)
{
    proto_sbv2 = proto_register_protocol(
        "GS SBv2",        /* name        */
        "sbv2",          /* short name  */
        "gs_sbv2"        /* filter_name */
    );
    proto_register_field_array(proto_sbv2, sbv2_fields_hf, array_length(sbv2_fields_hf));
    proto_register_subtree_array(sbv2_etts, array_length(sbv2_etts));
}


void proto_reg_handoff_sbv2(void)
{
    static dissector_handle_t sbv2_handle;

    sbv2_handle = create_dissector_handle(dissect_sbv2, proto_sbv2);
    dissector_add_uint("tcp.port", DEFAULT_SBV2_PORT, sbv2_handle);

}