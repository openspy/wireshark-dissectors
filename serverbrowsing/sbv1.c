#include "serverbrowsing.h"

int proto_sbv1 = -1;
gint proto_sbv1_ett = -1;

#define SBV1_VALIDATION_LEN 32

int sbv1_server_challenge = -1;
int sbv1_from_gamename = -1;
int sbv1_client_validation = -1;
int sbv1_validation_status = -1;
int sbv1_client_validation_expected = -1;
int sbv1_server_cmp_resp_ip = -1;
int sbv1_server_cmp_resp_port = -1;

static hf_register_info sbv1_fields_hf[] = {
    //crypt command properties
    { &sbv1_server_challenge,
        { "server_challenge", "sbv1.server_challenge",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_from_gamename,
        { "from_gamename", "sbv1.from_gamename",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_client_validation,
        { "client_validation", "sbv1.client_validation",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_validation_status,
        { "validation_status", "sbv1.validation_status",
        FT_BOOLEAN, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_client_validation_expected,
        { "client_validation_expected", "sbv1.client_validation_expected",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_server_cmp_resp_ip,
        { "server.cmplist.ip", "sbv1.server.cmplist.ip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &sbv1_server_cmp_resp_port,
        { "server.cmplist.port", "sbv1.server.cmplist.port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
};

enum EResponseType {
    EResponseType_PlainTextList,
    EResponseType_CompressedIPList
};

typedef struct _sbv1_conv_t {
    guint32	server_challenge_frame;
    guint32	client_validation_frame;
    guint32 client_request_frame;

    int enctype;
    enum EResponseType response_type;

    const char** query_from_game; //pointer to gslist_keys
    const char** query_for_game; //pointer to gslist_keys

    const char *server_challenge;
    const char *client_validation;
} sbv1_conv_t;
static gint* sbv1_etts[] = {
    &proto_sbv1_ett
};

static sbv1_conv_t* get_sbv1_conversation_data(packet_info* pinfo)
{
    conversation_t* conversation;
    sbv1_conv_t* conv_data;

    conversation = find_or_create_conversation(pinfo);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (sbv1_conv_t*)conversation_get_proto_data(conversation, proto_sbv1);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = (sbv1_conv_t*)wmem_alloc0(wmem_file_scope(), sizeof(sbv1_conv_t));

        conversation_add_proto_data(conversation, proto_sbv1,
            conv_data);
    }

    return conv_data;
}

int dissect_sbv1_server_challenge(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);
    conv->server_challenge_frame = pinfo->num;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV1 challenge");

    int offset = 15;
    const guint8 *temp_str;
    proto_tree_add_item_ret_string(tree, sbv1_server_challenge, tvb, offset, tvb_captured_length(tvb) - offset, ENC_ASCII, wmem_packet_scope(), &temp_str);

    if(conv->server_challenge == NULL) {
        conv->server_challenge = strdup(temp_str);
    }
    return tvb_captured_length(tvb);
}

int dissect_sbv1_server_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV1 server response");

    return tvb_captured_length(tvb);
}

int dissect_sbv1_client_validation(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV1 client response");

    //extract gamename
    int offset = 10; /* skip \\gamename\\ */
    int len = tvb_captured_length(tvb) - offset;
    tvbuff_t* buff = tvb_get_ptr(tvb, offset, len);
    const char *final = strstr((const char *)buff, "\\final\\");
    const char *s = strchr((const char *)buff, '\\');   
    if(s == NULL) {
        return tvb_captured_length(tvb); 
    } 
    int end = s - (const char *)buff;
    guint8 *gamename;
    proto_tree_add_item_ret_string(tree, sbv1_from_gamename, tvb, offset, end, ENC_ASCII, wmem_packet_scope(), &gamename);

    conv->query_from_game = gslist_keys_find_by_gamename(gamename, end);

    //extract validate response
    s = strstr((const char *)buff,"\\validate\\");
    if(s == NULL) {
        return tvb_captured_length(tvb); 
    }
    offset = (s) - (const char *)buff + 20; //+10 because of initial skipped data, plus \\validate\\ string
    

    int final_len = 0;
    if(final != NULL) {
        final_len = 7;
    }
    end = tvb_captured_length(tvb) - offset - final_len;

    guint8 *temp_str;
    proto_tree_add_item_ret_string(tree, sbv1_client_validation, tvb, offset, end, ENC_ASCII, wmem_packet_scope(), &temp_str);
    if(conv->client_validation == NULL) {
        conv->client_validation = strdup(temp_str);
    }

    char challenge_resp[90] = { 0 };
    proto_tree_add_string(tree, sbv1_client_validation_expected, tvb, offset, end, conv->server_challenge);
    gsseckey((unsigned char *)&challenge_resp, (const unsigned char *)conv->server_challenge, (const unsigned char *)conv->query_from_game[2], 0);

    if(strcmp(challenge_resp, (const unsigned char *)conv->client_validation) == 0) {
        proto_tree_add_boolean(tree, sbv1_validation_status, tvb, offset, end, 1);
    } else {
        proto_tree_add_string(tree, sbv1_client_validation_expected, tvb, offset, end, challenge_resp);
        proto_tree_add_boolean(tree, sbv1_validation_status, tvb, offset, end, 0);
    }

    return tvb_captured_length(tvb);
}
int dissect_sbv1_query_response_cmp_list(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) { 
    int offset = 0;
    int len = tvb_captured_length(tvb);
    while(offset < len) {
        uint32_t ip_addr = tvb_get_ntohl(tvb, offset);
        if(ip_addr == 0x5c66696e) { // \fin
            break;
        }
        proto_tree_add_item(tree, sbv1_server_cmp_resp_ip, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, sbv1_server_cmp_resp_port, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);
    }
    return tvb_captured_length(tvb);
}
int dissect_sbv1_query_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);
    switch(conv->response_type) {
        case EResponseType_CompressedIPList:
            return dissect_sbv1_query_response_cmp_list(tvb, pinfo, tree, data);
        break;
    }
    return tvb_captured_length(tvb);
}


int dissect_test(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {

    tvbuff_t* buff = tvb_get_ptr(tvb, 0, tvb_captured_length(tvb));

    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);
    conv->response_type = EResponseType_CompressedIPList;

    if(strncmp((const char *)buff, "\\gamename\\", 10) == 0) { //starts with gamenane, therefore it is the validaiton response
        return dissect_sbv1_client_validation(tvb, pinfo, tree, data);
    } else if(strncmp((const char *)buff, "\\list\\", 10) == 0) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV1 list req");

        conv->client_request_frame = pinfo->num;
    } else { //must be query request
         if(pinfo->can_desegment && pinfo->srcport == DEFAULT_SBV1_PORT) {
             pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
             pinfo->desegment_offset = 0;
             return 0;
        }
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBV1 query resp");
        return dissect_sbv1_query_response(tvb, pinfo, tree, data);
    }
    return tvb_captured_length(tvb);
}
static guint get_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_) {
    int len = tvb_captured_length(tvb) - offset;
    tvbuff_t* buff = tvb_get_ptr(tvb, offset, len);

    const char *s = strstr((const char *)buff, "\\final\\");

    if(s != NULL) {
        int diff = (int) (s - (const char *)buff);
        return diff + 7;
    }

    return len;
}

int dissect_sbv1(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    sbv1_conv_t* conv = get_sbv1_conversation_data(pinfo);

    if(conv->server_challenge_frame == 0 || conv->server_challenge_frame == pinfo->num) {
        return dissect_sbv1_server_challenge(tvb, pinfo, tree, data);
    } else {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0, get_message_len, dissect_test, data);
    }

    return tvb_captured_length(tvb);
}

void proto_register_sbv1(void)
{
    proto_sbv1 = proto_register_protocol(
        "GS SBv1",        /* name        */
        "sbv1",          /* short name  */
        "gs_sbv1"        /* filter_name */
    );
    proto_register_field_array(proto_sbv1, sbv1_fields_hf, array_length(sbv1_fields_hf));
    proto_register_subtree_array(sbv1_etts, array_length(sbv1_etts));
}


void proto_reg_handoff_sbv1(void)
{
    static dissector_handle_t sbv1_handle;

    sbv1_handle = create_dissector_handle(dissect_sbv1, proto_sbv1);
    dissector_add_uint("tcp.port", DEFAULT_SBV1_PORT, sbv1_handle);

}