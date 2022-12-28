#include "peerchat.h"

#include "gs_peerchat.h"

int proto_peerchat = -1;
gint proto_peerchat_ett = -1;

static gint* peerchat_etts[] = {
    &proto_peerchat_ett
};


int peerchat_crypt_gamename = -1;
int peerchat_challenge_client  = -1;
int peerchat_challenge_server = -1;

static hf_register_info peerchat_fields_hf[] = {
    //crypt command properties
    { &peerchat_crypt_gamename,
        { "crypt_gamename", "gs_peerchat.crypt_gamename",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },

    //challenge command properties
    { &peerchat_challenge_client,
        { "client_challenge", "gs_peerchat.challenge.client_challenge",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &peerchat_challenge_server,
        { "server_challenge", "gs_peerchat.challenge.server_challenge",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
};

static peerchat_conv_t* get_peerchat_conversation_data(packet_info* pinfo)
{
    conversation_t* conversation;
    peerchat_conv_t* conv_data;

    conversation = find_or_create_conversation(pinfo);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (peerchat_conv_t*)conversation_get_proto_data(conversation, proto_peerchat);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = (peerchat_conv_t*)wmem_alloc0(wmem_file_scope(), sizeof(peerchat_conv_t));

        conversation_add_proto_data(conversation, proto_peerchat,
            conv_data);
    }

    return conv_data;
}

static peerchat_pdu_crypto_state* get_peerchat_pdu_crypto_state(packet_info* pinfo) {
    conversation_t* conversation;
    peerchat_pdu_crypto_state* conv_data;

    conversation = find_or_create_conversation_by_id(pinfo, CONVERSATION_TCP, pinfo->num);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data = (peerchat_pdu_crypto_state*)conversation_get_proto_data(conversation, proto_peerchat);
    if (!conv_data) {
        /* Setup the conversation structure itself */
        conv_data = (peerchat_pdu_crypto_state*)wmem_alloc0(wmem_file_scope(), sizeof(peerchat_pdu_crypto_state));

        //copy latest crypto state
        peerchat_conv_t* peerchat_conv = get_peerchat_conversation_data(pinfo);

        if (pinfo->srcport == DEFAULT_PEERCHAT_PORT) { //copy server crypto state
            memcpy(&conv_data->state, &peerchat_conv->server_ctx, sizeof(conv_data->state));
        }
        else {
            memcpy(&conv_data->state, &peerchat_conv->client_ctx, sizeof(conv_data->state));
        }

        conversation_add_proto_data(conversation, proto_peerchat,
            conv_data);
    }

    return conv_data;
}

int dissect_peerchat_crypt(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    peerchat_conv_t* conv = get_peerchat_conversation_data(pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Peerchat Crypt");

    int offset = 0;

    conv->crypt_frame = pinfo->num;

    tvbuff_t* crypt_bytes = tvb_get_ptr(tvb, offset, tvb_captured_length(tvb));

    const char* last_space = strrchr((const char*)crypt_bytes, ' ');
    if (last_space != NULL) {
        last_space++;

        offset += last_space - (const char*)crypt_bytes;

        int remaining = tvb_captured_length_remaining(tvb, offset);
        remaining -= 2; //kinda nasty... skip \r\n

        conv->game_info = gslist_keys_find_by_gamename(last_space, remaining);

        proto_tree_add_item(tree, peerchat_crypt_gamename, tvb, offset, remaining, ENC_BIG_ENDIAN);
    }
    return tvb_captured_length(tvb);
}

int dissect_peerchat_challenge(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    peerchat_conv_t* conv = get_peerchat_conversation_data(pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Peerchat Challenge");

    int offset = 0;

    tvbuff_t* crypt_bytes = tvb_get_ptr(tvb, 0, tvb_captured_length(tvb));

    conv->challenge_frame = pinfo->num;

    const char* client_challenge = strrchr((const char*)crypt_bytes, '*'); //username is always * because they have not yet sent USER/NICK
    if (client_challenge != NULL) {
        client_challenge += 2; //skip "* "

        const char* server_challenge = strrchr(client_challenge, ' ');

        if (server_challenge != NULL) {
            server_challenge++; //skip space

            int client_challenge_len = server_challenge - client_challenge - 1;

            offset = client_challenge - (const char*)crypt_bytes;

            proto_tree_add_item(tree, peerchat_challenge_client, tvb, offset, PEERCHAT_CHALLENGE_LEN, ENC_BIG_ENDIAN);

            offset += PEERCHAT_CHALLENGE_LEN + 1; //challenge + space

            proto_tree_add_item(tree, peerchat_challenge_server, tvb, offset, PEERCHAT_CHALLENGE_LEN, ENC_BIG_ENDIAN);



            if (conv->challenge_setup == 0) {
                strncpy(conv->client_challenge, client_challenge, PEERCHAT_CHALLENGE_LEN);
                strncpy(conv->server_challenge, server_challenge, PEERCHAT_CHALLENGE_LEN);

                conv->challenge_setup = 1;
                gs_peerchat_init(&conv->client_ctx, conv->client_challenge, conv->game_info[2]);
                gs_peerchat_init(&conv->server_ctx, conv->server_challenge, conv->game_info[2]);
            }

        }
    }
    return tvb_captured_length(tvb);
}

int dissect_peerchat(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_) {
    peerchat_conv_t* conv = get_peerchat_conversation_data(pinfo);

    dissector_handle_t irc_handle = find_dissector("irc");

    if (conv->crypt_frame == 0) {
        tvbuff_t* crypt_bytes = tvb_get_ptr(tvb, 0, 5);
        if (crypt_bytes != NULL) {
            if (strncmp(crypt_bytes, "CRYPT", 5) == 0) {
                return dissect_peerchat_crypt(tvb, pinfo, tree, data);
            }
        }
    } 
    if ((conv->crypt_frame != 0 && conv->challenge_frame == 0 && pinfo->num > conv->crypt_frame) || pinfo->num == conv->challenge_frame) {
        return dissect_peerchat_challenge(tvb, pinfo, tree, data);
    }
    if (conv->crypt_frame == pinfo->num) {
        return dissect_peerchat_crypt(tvb, pinfo, tree, data);
    }

    if (conv->challenge_setup == 0) {
        return tvb_captured_length(tvb);
    }

    //decrypt and display data
    peerchat_pdu_crypto_state* pdu_state = get_peerchat_pdu_crypto_state(pinfo);

    

    guint16 decrypted_length = tvb_captured_length_remaining(tvb, 0); //no padding in peerchat, its just the packet length
    const char* original_buffer = (const char*)tvb_get_ptr(tvb, 0, decrypted_length);

    guchar* decrypted_heap_buffer = (guchar*)wmem_alloc(pinfo->pool, decrypted_length);
    memcpy(decrypted_heap_buffer, original_buffer, decrypted_length);

    gs_peerchat_ctx crypto_state;
    memcpy(&crypto_state, &pdu_state->state, sizeof(pdu_state->state));

    //this weird copy logic is to preserve the peerchat crypto state when you call out of order... ensure the state is saved and in the expected state for each PDU
    int copy_back = 0;
    if (pinfo->srcport == DEFAULT_PEERCHAT_PORT && conv->last_server_pdu < pinfo->num) { //copy server crypto state
        conv->last_server_pdu = pinfo->num;
        memcpy(&crypto_state, &conv->server_ctx, sizeof(pdu_state->state));
        memcpy(&pdu_state->state, &crypto_state, sizeof(pdu_state->state));
        copy_back = 1;
    }
    else if (pinfo->srcport != DEFAULT_PEERCHAT_PORT && conv->last_client_pdu < pinfo->num) {
        copy_back = 1;
        conv->last_client_pdu = pinfo->num;
        memcpy(&crypto_state, &conv->client_ctx, sizeof(pdu_state->state));
        memcpy(&pdu_state->state, &crypto_state, sizeof(pdu_state->state));
    }

    gs_peerchat(&crypto_state, decrypted_heap_buffer, decrypted_length);

    if (pinfo->srcport == DEFAULT_PEERCHAT_PORT && copy_back) {
        memcpy(&conv->server_ctx, &crypto_state, sizeof(pdu_state->state));
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Peerchat S->C");
    }
    else if (pinfo->srcport != DEFAULT_PEERCHAT_PORT && copy_back) {
        memcpy(&conv->client_ctx, &crypto_state, sizeof(pdu_state->state));
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Peerchat C->S");
    }

    tvbuff_t* decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_heap_buffer, decrypted_length, decrypted_length);
    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");
    
    call_dissector(irc_handle, decrypted_tvb, pinfo, tree, data);

    return tvb_captured_length(tvb);
}

void proto_register_peerchat(void)
{
    proto_peerchat = proto_register_protocol(
        "GS Peerchat",        /* name        */
        "peerchat",          /* short name  */
        "gs_perchat"        /* filter_name */
    );
    proto_register_field_array(proto_peerchat, peerchat_fields_hf, array_length(peerchat_fields_hf));
    proto_register_subtree_array(peerchat_etts, array_length(peerchat_etts));
}


void proto_reg_handoff_peerchat(void)
{
    static dissector_handle_t peerchat_handle;

    peerchat_handle = create_dissector_handle(dissect_peerchat, proto_peerchat);
    dissector_add_uint("tcp.port", DEFAULT_PEERCHAT_PORT, peerchat_handle);

}

void plugin_register_peerchat(void) {
    static proto_plugin natneg_plug;

    natneg_plug.register_protoinfo = proto_register_peerchat;
    natneg_plug.register_handoff = proto_reg_handoff_peerchat;
    proto_register_plugin(&natneg_plug);
}