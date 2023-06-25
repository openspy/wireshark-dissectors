#include "serverbrowsing.h"

int proto_sbv2 = -1;
gint proto_sbv2_ett = -1;

static gint* sbv2_etts[] = {
    &proto_sbv2_ett
};

int sbv2_incoming_length = -1;
int sbv2_request_type = -1;
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

unsigned char *enctypex_decoder(unsigned char *key, unsigned char *validate, unsigned char *data, int *datalen, enctypex_data_t *enctypex_data);

static hf_register_info sbv2_fields_hf[] = {
    //crypt command properties
    { &sbv2_incoming_length,
        { "incoming_length", "sbv2.incoming_length",
        FT_INT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv2_request_type,
        { "request_type", "sbv2.request_type",
        FT_UINT8, BASE_DEC,
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
};


enum EResponseType {
    EResponseType_PlainTextList,
    EResponseType_CompressedIPList
};

typedef struct _sbv2_conv_t {
    enctypex_data_t enctypex_data;
    char challenge[LIST_CHALLENGE_LEN];
    int last_server_pdu;
    const char** query_from_game; //pointer to gslist_keys
} sbv2_conv_t;

typedef struct _sbv2_pdu_crypto_state {
	enctypex_data_t state;
} sbv2_pdu_crypto_state;

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

        memcpy(&conv_data->state, &sbv2_conv->enctypex_data, sizeof(conv_data->state));

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
    offset += add_string_nts_item(tvb, tree, sbv2_listreq_from_gamename, offset);
    proto_tree_add_item(tree, sbv2_listreq_challenge, tvb, offset,  LIST_CHALLENGE_LEN, ENC_BIG_ENDIAN); offset += LIST_CHALLENGE_LEN;
    offset += add_string_nts_item(tvb, tree, sbv2_listreq_filter, offset);
    offset += add_string_nts_item(tvb, tree, sbv2_listreq_key_list, offset);

    guint32 options;
    proto_tree_add_item_ret_uint(tree, sbv2_listreq_options, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN, &options); offset += sizeof(uint32_t);

    if(options & ALTERNATE_SOURCE_IP) {
        proto_tree_add_item(tree, sbv2_listreq_source_ip, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    }
    if (options & LIMIT_RESULT_COUNT) {
        proto_tree_add_item(tree, sbv2_listreq_max_results, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    }

    //TODO: read challenge
    if(conv->query_from_game == NULL) {
        conv->challenge[0] = 0x30;
        conv->challenge[1] = 0x33;
        conv->challenge[2] = 0x2a;
        conv->challenge[3] = 0x45;
        conv->challenge[4] = 0x74;
        conv->challenge[5] = 0x67;
        conv->challenge[6] = 0x78;
        conv->challenge[7] = 0x5b;

        conv->query_from_game = gslist_keys_find_by_gamename("gslive", 6); //TODO: read proper gamename
    }

    return tvb_captured_length(tvb);
}

int dissect_sbv2_client_stream(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2");
    proto_tree_add_item(tree, sbv2_incoming_length, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);
    proto_tree_add_item(tree, sbv2_request_type, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN); offset += sizeof(uint8_t);
    return dissect_sbv2_list_request(tvb, pinfo, tree, data, offset);
}

static guint
    get_sbv2_incoming_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
{
    uint16_t message_length = tvb_get_ntohs(tvb, offset);
    return (guint)message_length;
}

int dissect_sbv2_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv2_conv_t *conv = get_sbv2_conversation_data(pinfo);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV2 response");

    enctypex_data_t crypto_state;
    
    int copy_back = 0;

    sbv2_pdu_crypto_state* pdu_state = get_sbv2_pdu_crypto_state(pinfo);
    memcpy(&crypto_state, &pdu_state->state, sizeof(pdu_state->state));

    guint32 decrypted_length = tvb_captured_length_remaining(tvb, 0);
    const char* original_buffer = (const char*)tvb_get_ptr(tvb, 0, decrypted_length);

    guchar* decrypted_heap_buffer = (guchar*)wmem_alloc(pinfo->pool, decrypted_length);
    memcpy(decrypted_heap_buffer, original_buffer, decrypted_length);

    if (conv->last_server_pdu < pinfo->num) { //copy server crypto state
        conv->last_server_pdu = pinfo->num;
        memcpy(&crypto_state, &conv->enctypex_data, sizeof(pdu_state->state));
        memcpy(&pdu_state->state, &crypto_state, sizeof(pdu_state->state));
        copy_back = 1;
    }

    //unsigned char *enctypex_decoder(unsigned char *key, unsigned char *validate, unsigned char *data, int *datalen, enctypex_data_t *enctypex_data);
    //decrypt
    unsigned char *dec_data = enctypex_decoder(conv->query_from_game[2], (unsigned char *)&conv->challenge, decrypted_heap_buffer, &decrypted_length, &crypto_state);

    if (copy_back) {
        memcpy(&conv->enctypex_data, &crypto_state, sizeof(conv->enctypex_data));
    }

    tvbuff_t* decrypted_tvb = tvb_new_child_real_data(tvb, dec_data, decrypted_length, decrypted_length);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");
    
    return tvb_captured_length(tvb);
}

int dissect_sbv2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) { 

    if(pinfo->srcport != DEFAULT_SBV2_PORT) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_sbv2_incoming_message_len, dissect_sbv2_client_stream, data);
    } else {
        return dissect_sbv2_response(tvb, pinfo, tree, data);
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