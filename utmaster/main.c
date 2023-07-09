#include "main.h"

    #define FRAME_HEADER_LEN 4


    int proto_utms = -1;


    gint list_req_ett_foo = -1;

    int fstrlen_field = -1;
    int fstring_field = -1;
    int msgid_field = -1;
    int msglen_field = -1;
    int msgname_field = -1;


    //server challenge fields
    int challenge_field = -1;

    //client challenge response fields
    int cdkey_hash_field = -1;
    int cdkey_response_field = -1;
    int client_name_field = -1;
    int running_version_field = -1;
    int running_os_field = -1;
    int language_field = -1;
    int gpu_device_id_field = -1;
    int gpu_vendor_id_field = -1;
    int cpu_cycles_field = -1;
    int running_cpu_field = -1;

    //server validation response
    int validation_response_status_field = -1;
    int validation_response_unknown_field = -1;
    
    //client verification fields
    int client_verification_data_field = -1;

    //server verification response fields
    int server_verification_status_field = -1;

    //motd response fields
    int motd_response_msg_field = -1;
    int motd_response_unknown = -1;

    //server list request fields
    int server_list_req_properties_count_field = -1;
    int server_list_req_filter_name = -1;
    int server_list_req_filter_value = -1;
    int server_list_req_filter_type = -1;
    int server_list_req_filter_type_name = -1;

    //server list response fields
    int server_list_resp_num_servers = -1;
    int server_list_resp_ip_address = -1;
    int server_list_resp_game_port = -1;
    int server_list_resp_query_port = -1;
    int server_list_resp_hostname = -1;
    int server_list_resp_level = -1;
    int server_list_resp_game_group = -1;
    int server_list_resp_num_players = -1;
    int server_list_resp_max_players = -1;
    int server_list_resp_server_flags = -1;
    int server_list_resp_bot_settings = -1;
    int server_list_resp_unk1 = -1;

    //server info fields
    int server_info_behind_nat = -1;
    int server_info_gamespy_uplink = -1;

    //server uplink info response fields
    int server_hb_request_id_field = -1;
    int server_hb_request_code_field = -1;

    //inform match id fields
    int server_inform_match_id_field = -1;

    //hb submission fields
    int server_hb_submit_num_addresses = -1;
    int server_hb_submit_address = -1;
    int server_hb_server_id = -1;
    int server_hb_server_address = -1;
    int server_hb_gameport = -1;
    int server_hb_queryport = -1;
    int server_hb_submit_hostname = -1;
    int server_hb_submit_level = -1;
    int server_hb_submit_gamegroup = -1;
    int server_hb_submit_numplayers = -1;
    int server_hb_submit_maxplayers = -1;
    int server_hb_submit_ping = -1;
    int server_hb_submit_flags = -1;
    int server_hb_submit_skilllevel = -1;
    int server_hb_submit_numfields = -1;
    int server_hb_submit_field = -1;
    int server_hb_submit_property = -1;
    int server_hb_submit_num_player_entries = -1;
    int server_hb_submit_player_name = -1;
    int server_hb_submit_player_id = -1;
    int server_hb_submit_player_ping = -1;
    int server_hb_submit_player_score = -1;
    int server_hb_submit_player_statsid= -1;

    //stats update
    int server_statsupdate_statsdata = -1;

    //server detected ports info
    int server_detected_ports_heartbeat_secs = -1;
    int server_detected_port_1 = -1;
    int server_detected_port_2 = -1;
    int server_detected_port_3 = -1;

    //packages data (server to client)
    int packages_data_num_packages = -1;
    int packages_data_guid = -1;
    int packages_data_md5 = -1;
    int packages_data_revision = -1;

    //packages data (client to server)
    int packages_data_current_revision = -1;


    //UT Query
    int utquery_version_field = -1;
    int utquery_type_field = -1;


    int temp_buffer_field = -1;

    static hf_register_info standard_fields_hf[] = {
        { &temp_buffer_field,
            { "temp_buffer", "utms.temp_buffer",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &fstrlen_field,
            { "fstrlen", "utms.fstrlen",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &fstring_field,
            { "fstring", "utms.fstring",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &msgid_field,
            { "msgid", "utms.msgid",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &msgname_field,
            { "msgname", "utms.msgname",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &msglen_field,
            { "msglen", "utms.msglen",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &challenge_field,
            { "challenge", "utms.challenge",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        //client challenge response fields
        { &cdkey_hash_field,
            { "cdkey_hash", "utms.client_challenge_resp.cdkey_hash",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &cdkey_response_field,
            { "cdkey_response", "utms.client_challenge_resp.cdkey_response",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &client_name_field,
            { "client_name", "utms.client_challenge_resp.client_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &running_version_field,
            { "running_version", "utms.client_challenge_resp.running_version",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &running_os_field,
            { "running_os", "utms.client_challenge_resp.running_os",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &language_field,
            { "language", "utms.client_challenge_resp.language",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &gpu_device_id_field,
            { "gpu_device_id", "utms.client_challenge_resp.gpu_device_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &gpu_vendor_id_field,
            { "gpu_vendor_id", "utms.client_challenge_resp.gpu_vendor_id",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &cpu_cycles_field,
            { "cpu_cycles", "utms.client_challenge_resp.cpu_cycles",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &running_cpu_field,
            { "running_cpu", "utms.client_challenge_resp.running_cpu",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        //server validation response
        { &validation_response_status_field,
            { "status", "utms.server_validation_response.status",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &validation_response_unknown_field,
            { "validation_response_unknown", "utms.server_validation_response.unknown",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        //client verification fields
        { &client_verification_data_field,
            { "data", "utms.client_verification.data",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        //server verification response fields
        { &server_verification_status_field,
            { "status", "utms.server_verification_resp.status",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
         //motd response fields
        { &motd_response_msg_field,
            { "motd", "utms.motd_response.motd",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &motd_response_unknown,
             { "motd_unknown", "utms.motd_response.unknown",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_req_properties_count_field,
             { "num_properties", "utms.server_list_req.num_properties",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_req_filter_name,
             { "filter_name", "utms.server_list_req.filter_name",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_req_filter_value,
             { "filter_value", "utms.server_list_req.filter_value",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
       { &server_list_req_filter_type,
            { "filter_type", "utms.server_list_req.filter_type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
       },
        { &server_list_req_filter_type_name,
             { "filter_type_name", "utms.server_list_req.filter_type_name",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },

        //server list response
        { &server_list_resp_num_servers,
             { "num_servers", "utms.server_list_resp.num_servers",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_unk1,
            { "unk1", "utms.server_list_resp.unk1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &server_list_resp_ip_address,
             { "ip_address", "utms.server_list_resp.ip_address",
             FT_IPv4, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_game_port,
             { "game_port", "utms.server_list_resp.game_port",
             FT_UINT16, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_query_port,
             { "query_port", "utms.server_list_resp.query_port",
             FT_UINT16, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_hostname,
             { "hostname", "utms.server_list_resp.hostname",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_level,
             { "level", "utms.server_list_resp.level",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_game_group,
             { "game_group", "utms.server_list_resp.game_group",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_num_players,
             { "num_players", "utms.server_list_resp.num_players",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_max_players,
             { "max_players", "utms.server_list_resp.max_players",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_server_flags,
             { "flags", "utms.server_list_resp.flags",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_list_resp_bot_settings,
             { "bot_settings", "utms.bot_settings.bot_settings",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
            //server info
        { &server_info_behind_nat,
             { "behind_nat", "utms.server_info.behind_nat",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_info_gamespy_uplink,
             { "gamespy_uplink", "utms.server_info.gamespy_uplink",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
            //server heartbeat req
        { &server_hb_request_id_field,
             { "id", "utms.hb_request.id",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_request_code_field,
             { "heartbeat_code", "utms.hb_request.heartbeat_code",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
            //match id inform
        { &server_inform_match_id_field,
             { "matchid", "utms.inform_matchid.matchid",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        //gameserver heartbeat submission fields
        { &server_hb_submit_num_addresses,
             { "num_addresses", "utms.heartbeat.num_addresses",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_address,
             { "address", "utms.heartbeat.address",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },            
        { &server_hb_server_id,
             { "server_id", "utms.heartbeat.server_id",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_server_address,
             { "server_address", "utms.heartbeat.server_address",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
            
        { &server_hb_gameport,
             { "gameport", "utms.heartbeat.gameport",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_queryport,
             { "queryport", "utms.heartbeat.queryport",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_hostname,
             { "hostname", "utms.heartbeat.hostname",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_level,
             { "level", "utms.heartbeat.level",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_gamegroup,
             { "gamegroup", "utms.heartbeat.gamegroup",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        }, 
        { &server_hb_submit_numplayers,
             { "num_players", "utms.heartbeat.num_players",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_maxplayers,
             { "max_players", "utms.heartbeat.max_players",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_ping,
             { "ping", "utms.heartbeat.ping",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_flags,
             { "flags", "utms.heartbeat.flags",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_skilllevel,
             { "skilllevel", "utms.heartbeat.skilllevel",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_numfields,
             { "num_fields", "utms.heartbeat.num_fields",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_field,
             { "field", "utms.heartbeat.field",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_property,
             { "property", "utms.heartbeat.property",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_num_player_entries,
             { "num_player_entries", "utms.heartbeat.num_player_entries",
             FT_UINT8, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_player_name,
             { "player_name", "utms.heartbeat.player_name",
             FT_STRING, BASE_NONE,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_player_id,
             { "player_id", "utms.heartbeat.player_id",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_player_ping,
             { "player_ping", "utms.heartbeat.player_ping",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_player_score,
             { "player_score", "utms.heartbeat.player_score",
             FT_UINT32, BASE_DEC,
             NULL, 0x0,
             NULL, HFILL }
        },
        { &server_hb_submit_player_statsid,
              { "player_statsid", "utms.heartbeat.player_statsid",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },

        //stats update
        { &server_statsupdate_statsdata,
              { "stats_data", "utms.stats_update.stats_data",
              FT_STRING, BASE_NONE,
              NULL, 0x0,
              NULL, HFILL }
        },

         //server detected ports info
        { &server_detected_ports_heartbeat_secs,
              { "heartbeat_secs", "utms.detected_ports.heartbeat_secs",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &server_detected_port_1,
              { "port_1", "utms.detected_ports.port_1",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &server_detected_port_2,
              { "port_2", "utms.detected_ports.port_2",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &server_detected_port_3,
              { "port_3", "utms.detected_ports.port_3",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        //packages data
        { &packages_data_num_packages,
              { "num_packages", "utms.packages_update.num_packages",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &packages_data_guid,
              { "guid", "utms.packages_update.guid",
              FT_STRING, BASE_NONE,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &packages_data_md5,
              { "md5", "utms.packages_update.md5",
              FT_STRING, BASE_NONE,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &packages_data_revision,
              { "revision", "utms.packages_update.revision",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },

        { &packages_data_current_revision,
              { "current_revision", "utms.packages_update.current_revision",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },

        //ut query stuff
        { &utquery_version_field,
              { "version", "utquery.version",
              FT_UINT32, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },
        { &utquery_type_field,
              { "type", "utquery.type",
              FT_UINT8, BASE_DEC,
              NULL, 0x0,
              NULL, HFILL }
        },

    };


    static gint* list_req_ett[] = {
        &list_req_ett_foo
    };

    static utms_request_name_mapping request_name_mapping[] = {
        {EClientModeRequest_ServerList, 0, "Server List Request", "Server List Response"},
        {EClientModeRequest_MOTD, 0, "MOTD Request", "MOTD Response"},
        //gameserver requests
        {EServerModeRequest_HeartbeatReq, 1, "Heartbeat Request (??)", "Heartbeat Request"},
        {EServerModeRequest_Heartbeat, 1, "Heartbeat", "Detected Ports"},
        {EServerModeRequest_StatsUpdate, 1, "Stats Update", "Stats Update (??)"},
        {EServerModeRequest_InformMatchID, 1, "Inform Match ID (??)", "Inform Match ID"},
        {EServerModeRequest_PackagesUpdate, 1, "Packages Version", "Packages Data"},
        
    };

    const char* get_request_name(uint8_t msgid, uint8_t is_server) {
        for (int i = 0; i < sizeof(request_name_mapping) / sizeof(utms_request_name_mapping); i++) {
            utms_request_name_mapping* entry = (utms_request_name_mapping*)&request_name_mapping[i];

            if (entry->is_server_mode == is_server && entry->request_id == msgid) {
                return entry->name;
            }
        }
        return "Unknown Request";
    }

    const char* get_request_response_name(uint8_t msgid, uint8_t is_server) {
        for (int i = 0; i < sizeof(request_name_mapping) / sizeof(utms_request_name_mapping); i++) {
            utms_request_name_mapping* entry = (utms_request_name_mapping*)&request_name_mapping[i];

            if (entry->is_server_mode == is_server && entry->request_id == msgid) {
                return entry->response_name;
            }
        }
        return "Unknown Response";
    }


    static utms_conv_t* get_utms_conversation_data(packet_info* pinfo)
    {
        conversation_t* conversation;
        utms_conv_t* conv_data;

        conversation = find_or_create_conversation(pinfo);

        /* Retrieve information from conversation
         * or add it if it isn't there yet
         */
        conv_data = (utms_conv_t*)conversation_get_proto_data(conversation, proto_utms);
        if (!conv_data) {
            /* Setup the conversation structure itself */
            conv_data = (utms_conv_t*)wmem_alloc0(wmem_file_scope(), sizeof(utms_conv_t));

            conversation_add_proto_data(conversation, proto_utms,
                conv_data);
        }

        return conv_data;
    }


    int DecodeCompact(tvbuff_t* tvb, int *Count, int offset)
    {
        int Value = 0;

        *Count = 1;

        char B[5];

        B[0] = tvb_get_guint8(tvb, offset++);
        if ((B[0] & 0x40) != 0)
        {
            B[1] = tvb_get_guint8(tvb, offset++);
            *Count = *Count + 1;
            if ((B[1] & 0x80) != 0)
            {
                B[2] = tvb_get_guint8(tvb, offset++);
                *Count = *Count + 1;
                if ((B[2] & 0x80) != 0)
                {
                    B[3] = tvb_get_guint8(tvb, offset++);
                    *Count = *Count + 1;
                    if ((B[3] & 0x80) != 0)
                    {
                        B[4] = tvb_get_guint8(tvb, offset++);
                        *Count = *Count + 1;
                        Value = B[4];
                    }
                    Value = (Value << 7) + (B[3] & 0x7f);
                }
                Value = (Value << 7) + (B[2] & 0x7f);
            }
            Value = (Value << 7) + (B[1] & 0x7f);
        }
        Value = (Value << 6) + (B[0] & 0x3f);
        if ((B[0] & 0x80) != 0)
            Value = -Value;
        return Value;
    }

    static struct _utms_pdu_data* get_pdu_specific_data(packet_info* pinfo) {
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        int first_free_id = -1;
        for (int i = 0; i < MAX_SERVER_MESSAGES_PER_CONNECTION; i++) {
            struct _utms_pdu_data* item = &conv_data->pdu_request_mapping[i];

            if (item->pdu_id == 0 && item->request_id == 0 && first_free_id == -1) {
                first_free_id = i;
            }

            if (item->pdu_id == pinfo->fd->num) {
                return item;
            }
        }

        if (first_free_id != -1) {
            return &conv_data->pdu_request_mapping[first_free_id];
        }

        return NULL;
    }

    void dissect_fstring(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int* offset, int field) {
        int count = 0;
        int length = DecodeCompact(tvb, &count, *offset);

        //proto_tree_add_int(tree, fstrlen_field, tvb, *offset, count, length);
        *offset += count;

        proto_tree_add_item(tree, field, tvb, *offset, length, ENC_LITTLE_ENDIAN); *offset += length;
    }

    const tvbuff_t* fstring_get_tvb(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset) {
        int fstring_len_size = 0;
        int length = DecodeCompact(tvb, &fstring_len_size, offset); offset += fstring_len_size;

        return tvb_get_ptr(tvb, offset, fstring_len_size);
    }

    /* determine PDU length of protocol foo */
    static guint
        get_utms_message_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset, void* data _U_)
    {
        uint32_t message_length = tvb_get_letohil(tvb, offset);
        
        return (guint)message_length + 4;
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_server_challenge(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        int offset = 0;

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        dissect_fstring(tvb, pinfo, tree, data, &offset, challenge_field);

        /* TODO: implement your dissecting code */
        return tvb_captured_length(tvb);
    }


    /* This method dissects fully reassembled messages */
    static int
        dissect_client_challenge_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {

        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        int offset = 0;

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);


        dissect_fstring(tvb, pinfo, tree, data, &offset, cdkey_hash_field);
        dissect_fstring(tvb, pinfo, tree, data, &offset, cdkey_response_field);
    

        const tvbuff_t* client_name_buf = fstring_get_tvb(tvb, pinfo, tree, data, offset);
        const char* client_name = (const char*)client_name_buf;

        if (strstr(client_name, "SERVER") != NULL) {
            conv_data->utms_is_gameserver = 1;
        }

        dissect_fstring(tvb, pinfo, tree, data, &offset, client_name_field);

        //utms_client_version
        proto_tree_add_item_ret_uint(tree, running_version_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &conv_data->utms_client_version); offset += sizeof(uint32_t);
        if (conv_data->utms_client_version < 3000 && conv_data->utms_is_gameserver) {
            proto_tree_add_item(tree, temp_buffer_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t); //unknown data
        }
        proto_tree_add_item(tree, running_os_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);

        dissect_fstring(tvb, pinfo, tree, data, &offset, language_field);

        if (conv_data->utms_client_version >= 3000) {
            guint32 gpu_device;
            proto_tree_add_item_ret_uint(tree, gpu_device_id_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &gpu_device); offset += sizeof(uint32_t);
            if (!conv_data->utms_is_gameserver) {
                proto_tree_add_item(tree, gpu_vendor_id_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
                proto_tree_add_item(tree, cpu_cycles_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            }

            proto_tree_add_item(tree, running_cpu_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);

        }

        /* TODO: implement your dissecting code */
        return tvb_captured_length(tvb);
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_server_validation_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        int offset = 0;
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        dissect_fstring(tvb, pinfo, tree, data, &offset, validation_response_status_field);

        if (conv_data->utms_client_version >= 3000 && !conv_data->utms_is_gameserver) {
            proto_tree_add_item(tree, validation_response_unknown_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }
        
        return tvb_captured_length(tvb);
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_client_verification(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        int offset = 0;
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        if (conv_data->utms_client_version >= 3000) {
            dissect_fstring(tvb, pinfo, tree, data, &offset, client_verification_data_field);
        }
        return tvb_captured_length(tvb);
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_server_uplink_info(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        int offset = 0;

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        proto_tree_add_item(tree, server_info_behind_nat, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, server_info_gamespy_uplink, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        return tvb_captured_length(tvb);
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_server_heartbeat_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        proto_tree_add_item(tree, server_hb_request_id_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
        proto_tree_add_item(tree, server_hb_request_code_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        return tvb_captured_length(tvb);
    }

    static int
        dissect_server_inform_detected_ports(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        if (conv_data->utms_client_version < 3000) {
            proto_tree_add_item(tree, server_detected_ports_heartbeat_secs, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
            proto_tree_add_item(tree, server_detected_port_1, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }
        else {
            proto_tree_add_item(tree, server_detected_ports_heartbeat_secs, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_detected_port_1, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_detected_port_2, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_detected_port_3, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }

        return tvb_captured_length(tvb);
    }

    /* This method dissects fully reassembled messages */
    static int
        dissect_server_uplink_info_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        int offset = 0;

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        dissect_fstring(tvb, pinfo, tree, data, &offset, server_verification_status_field);
        return tvb_captured_length(tvb);
    }

    static int
        dissect_client_server_list_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int *offset) {

        guint32 num_filter_fields;
        guint32 filter_type;
        proto_tree_add_item_ret_uint(tree, server_list_req_properties_count_field, tvb, *offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_filter_fields); *offset += sizeof(uint8_t);
        for (guint32 i = 0; i < num_filter_fields; i++) {
            dissect_fstring(tvb, pinfo, tree, data, offset, server_list_req_filter_name);
            dissect_fstring(tvb, pinfo, tree, data, offset, server_list_req_filter_value);
            proto_tree_add_item_ret_uint(tree, server_list_req_filter_type, tvb, *offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &filter_type); 

            switch (filter_type) {
            case QT_Equals:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "Equals");
                break;
            case QT_NotEquals:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "NotEquals");
                break;
            case QT_LessThan:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "LessThan");
                break;
            case QT_LessThanEquals:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "LessThanEquals");
                break;
            case QT_GreaterThan:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "GreaterThan");
                break;
            case QT_GreaterThanEquals:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "GreaterThanEquals");
                break;
            case QT_Disabled:
                proto_tree_add_string(tree, server_list_req_filter_type_name, tvb, *offset, sizeof(uint8_t), "Disabled");
                break;
            }
            *offset += sizeof(uint8_t);
        }
        return tvb_captured_length(tvb);
    }
    
    static int dissect_gameserver_stats_update(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset) {
        utms_conv_t* conv_data = (utms_conv_t*)data;

        dissect_fstring(tvb, pinfo, tree, data, &offset, server_statsupdate_statsdata);

        return tvb_captured_length(tvb);
    }
    static int
        dissect_gameserver_heartbeat_req(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset) {
        utms_conv_t* conv_data = (utms_conv_t*)data;
        guint32 num_addresses;
        proto_tree_add_item_ret_uint(tree, server_hb_submit_num_addresses, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_addresses); offset += sizeof(uint8_t);

        for (int i = 0; i < num_addresses; i++) {
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_address);
        }

        
        proto_tree_add_item(tree, server_hb_server_id, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_server_address);

        proto_tree_add_item(tree, server_hb_gameport, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, server_hb_queryport, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);


        dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_hostname);
        dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_level);
        dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_gamegroup);

        proto_tree_add_item(tree, server_hb_submit_numplayers, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, server_hb_submit_maxplayers, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, server_hb_submit_ping, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        


        if (conv_data->utms_client_version >= 3000) {
            proto_tree_add_item(tree, server_hb_submit_flags, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_skilllevel);
        }

        guint32 num_fields;
        proto_tree_add_item_ret_uint(tree, server_hb_submit_numfields, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_fields); offset += sizeof(uint8_t);
        for (int i = 0; i < num_fields; i++) {
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_field);
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_property);
        }

        proto_tree_add_item_ret_uint(tree, server_hb_submit_num_player_entries, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_fields); offset += sizeof(uint8_t);
        for (int i = 0; i < num_fields; i++) {            
            proto_tree_add_item(tree, server_hb_submit_player_id, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_player_name);
            proto_tree_add_item(tree, server_hb_submit_player_ping, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_hb_submit_player_score, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_hb_submit_player_statsid, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }
        return tvb_captured_length(tvb);
    }

    static int dissect_gameserver_packages_version(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset) {
        utms_conv_t* conv_data = (utms_conv_t*)data;
        proto_tree_add_item(tree, packages_data_current_revision, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        return tvb_captured_length(tvb);
    }
    static int
        dissect_client_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        utms_conv_t* conv_data = (utms_conv_t*)data;

        int offset = 0;
        guint32 msgid;
        guint32 msglen;
        proto_tree_add_item_ret_uint(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &msglen); offset += sizeof(uint32_t);
        proto_tree_add_item_ret_uint(tree, msgid_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &msgid); offset += sizeof(uint8_t);

        if (conv_data->utms_is_gameserver) {
            const char* request_name = get_request_name(msgid, 1);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);

            switch (msgid) {
                case EServerModeRequest_Heartbeat:
                    return dissect_gameserver_heartbeat_req(tvb, pinfo, tree, data, offset);
                    break;
                case EServerModeRequest_StatsUpdate:
                    return dissect_gameserver_stats_update(tvb, pinfo, tree, data, offset);
                case EServerModeRequest_PackagesUpdate:
                    return dissect_gameserver_packages_version(tvb, pinfo, tree, data, offset);
                default:
                    proto_tree_add_item(tree, temp_buffer_field, tvb, offset, msglen - 1, ENC_LITTLE_ENDIAN); offset += msglen - 1;
               break;
            }
        }
        else {
            
            const char* request_name = get_request_name(msgid, 0);

            if (request_name != NULL) {
                proto_tree_add_string(tree, msgname_field, tvb, offset - 1, sizeof(uint8_t), request_name); //-1 to show in same place as msg id
                col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);
            }
            else {
                proto_tree_add_string(tree, msgname_field, tvb, offset - 1, sizeof(uint8_t), "Unknown"); //-1 to show in same place as msg id
            }
            conv_data->last_client_request_id = msgid;

            switch (msgid) {
            case EClientModeRequest_ServerList:
                dissect_client_server_list_request(tvb, pinfo, tree, data, &offset);
                break;

            }
        }

        return tvb_captured_length(tvb);
    }

    static int
        dissect_server_motd_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);
        const char* request_name = get_request_response_name(EClientModeRequest_MOTD, 0);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);
        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        dissect_fstring(tvb, pinfo, tree, data, &offset, motd_response_msg_field);

        if (conv_data->utms_client_version >= 3000) {
            proto_tree_add_item(tree, motd_response_unknown, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }
        
    }

    static int
        dissect_server_list_entry(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        const char* request_name = get_request_response_name(EClientModeRequest_ServerList, 0);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);

        guint32 buff_len;
        proto_item* ti = proto_tree_add_item(tree, proto_utms, tvb, 0, -1, ENC_NA);
        proto_tree* subtree = proto_item_add_subtree(ti, list_req_ett_foo);
        proto_item_set_text(subtree, "Server Item");

        proto_tree_add_item_ret_uint(subtree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &buff_len); offset += sizeof(uint32_t);
        proto_tree_add_item(subtree, server_list_resp_ip_address, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
        proto_tree_add_item(subtree, server_list_resp_game_port, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint16_t);
        proto_tree_add_item(subtree, server_list_resp_query_port, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint16_t);
        dissect_fstring(tvb, pinfo, subtree, data, &offset, server_list_resp_hostname);
        dissect_fstring(tvb, pinfo, subtree, data, &offset, server_list_resp_level);
        dissect_fstring(tvb, pinfo, subtree, data, &offset, server_list_resp_game_group);
        proto_tree_add_item(subtree, server_list_resp_num_players, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
        proto_tree_add_item(subtree, server_list_resp_max_players, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
        proto_tree_add_item(subtree, server_list_resp_server_flags, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        if (conv_data->utms_client_version >= 3000) {
            dissect_fstring(tvb, pinfo, subtree, data, &offset, server_list_resp_bot_settings);
        }
        return tvb_captured_length(tvb);
    }


    /* determine PDU length of protocol foo */

    static int
        dissect_server_list_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        utms_conv_t* conv_data = get_utms_conversation_data(pinfo);

        const char* request_name = get_request_response_name(EClientModeRequest_ServerList, 0);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);

        proto_tree_add_item(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

        guint32 total_servers;
        proto_tree_add_item_ret_uint(tree, server_list_resp_num_servers, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &total_servers); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, server_list_resp_unk1, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t); //is compressed list
        //





        return tvb_captured_length(tvb);
    }

    static int
        dissect_server_packages_data(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_, int offset)
    {
        guint32 total_packages;

        int count = 0;
        int length = DecodeCompact(tvb, &count, offset);
        proto_tree_add_uint(tree, packages_data_num_packages, tvb, offset, count, length);
        offset += count;

        total_packages = length;

        for (int i = 0; i < total_packages; i++) {
            dissect_fstring(tvb, pinfo, tree, data, &offset, packages_data_guid);
            dissect_fstring(tvb, pinfo, tree, data, &offset, packages_data_md5);
            proto_tree_add_item(tree, packages_data_revision, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
        }

        return tvb_captured_length(tvb);
    }

    static int
        dissect_server_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
    {
        struct _utms_pdu_data* pdu_data = get_pdu_specific_data(pinfo);

        utms_conv_t* conv_data = (utms_conv_t*)data;

        if (pdu_data != NULL && pdu_data->request_id == 0) {
            pdu_data->request_id = conv_data->last_client_request_id;
        }

        int offset = 0;

        guint32 buff_len;

        if (pdu_data != NULL) {
            if (!conv_data->utms_is_gameserver) {
                const char* request_name = get_request_response_name(pdu_data->request_id, 0);
                switch (pdu_data->request_id) {
                case EClientModeRequest_MOTD:
                    return dissect_server_motd_response(tvb, pinfo, tree, data, offset);
                    break;
                case EClientModeRequest_ServerList:
                    if (tvb_captured_length_remaining(tvb, offset) == 5+4) { //really lame check for if its a server list header vs item... need a better way
                        return dissect_server_list_response(tvb, pinfo, tree, data, offset);
                    }
                    else {
                        return dissect_server_list_entry(tvb, pinfo, tree, data, offset);
                    }
                    break;
                }
            }
            else {
                guint32 msgid;
                proto_tree_add_item_ret_uint(tree, msglen_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &buff_len); offset += sizeof(uint32_t);
                proto_tree_add_item_ret_uint(tree, msgid_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &msgid); offset += sizeof(uint8_t);

                const char* request_name = get_request_response_name(msgid, 1);
                col_set_str(pinfo->cinfo, COL_PROTOCOL, request_name);
                switch (msgid) {
                    case EServerModeRequest_HeartbeatReq:                                           
                        return dissect_server_heartbeat_request(tvb, pinfo, tree, data, offset);
                        break;
                    case EServerModeRequest_Heartbeat:
                        return dissect_server_inform_detected_ports(tvb, pinfo, tree, data, offset);
                        break;
                    case EServerModeRequest_InformMatchID:
                        proto_tree_add_item_ret_uint(tree, server_inform_match_id_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &buff_len); offset += sizeof(uint32_t);
                        break;
                    case EServerModeRequest_PackagesUpdate: //packages update
                        return dissect_server_packages_data(tvb, pinfo, tree, data, offset);
                    break;
                    default:
                        proto_tree_add_item(tree, temp_buffer_field, tvb, offset, buff_len - 1, ENC_LITTLE_ENDIAN);
                        offset += buff_len;                        
                        return tvb_captured_length(tvb);
                }
            }

        }
        else {
            //unknown response
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "unknown response");
        }
        return tvb_captured_length(tvb);
    }

    static int
        dissect_utms(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
    {
        utms_conv_t *conv_data = get_utms_conversation_data(pinfo);
        if (conv_data->server_challenge_frame == 0 && !pinfo->fd->visited)
            conv_data->server_challenge_frame = pinfo->fd->num;

        else if (pinfo->fd->num > conv_data->server_challenge_frame && conv_data->client_challenge_response_frame == 0 && !pinfo->fd->visited)
            conv_data->client_challenge_response_frame = pinfo->fd->num;
        
        else if (pinfo->fd->num > conv_data->client_challenge_response_frame && conv_data->server_client_challenge_response_frame == 0 && !pinfo->fd->visited) {
            conv_data->server_client_challenge_response_frame = pinfo->fd->num;
        }
        else if (pinfo->fd->num > conv_data->server_client_challenge_response_frame && conv_data->client_verification_frame == 0 && !pinfo->fd->visited) {
            conv_data->client_verification_frame = pinfo->fd->num;
        }
        else if (pinfo->fd->num > conv_data->client_verification_frame && conv_data->server_verification_response_frame == 0 && !pinfo->fd->visited) {
            conv_data->server_verification_response_frame = pinfo->fd->num;
        }

        proto_item* ti = proto_tree_add_item(tree, proto_utms, tvb, 0, -1, ENC_NA);
        tree = proto_item_add_subtree(ti, list_req_ett_foo);

        if (conv_data->server_challenge_frame == pinfo->fd->num) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Server Challenge");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_server_challenge, data);
        } else if (conv_data->client_challenge_response_frame == pinfo->fd->num) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Client Response");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_client_challenge_response, data);
        }
        else if (conv_data->server_client_challenge_response_frame == pinfo->fd->num) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Server Validation Response");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_server_validation_response, data);
        }
        else if (conv_data->client_verification_frame == pinfo->fd->num && !conv_data->utms_is_gameserver && conv_data->utms_client_version >= 3000) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Client Verification");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_client_verification, data);
        }
        else if (conv_data->server_verification_response_frame == pinfo->fd->num && !conv_data->utms_is_gameserver && conv_data->utms_client_version >= 3000) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Server Verification Response");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_client_verification, data);
        }
        else if (conv_data->client_verification_frame == pinfo->fd->num && conv_data->utms_is_gameserver) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Server Uplink Info");
            tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                get_utms_message_len, dissect_server_uplink_info, data);
        }
        else if(!conv_data->utms_is_gameserver) {
            if (pinfo->srcport == DEFAULT_MS_PORT) {
                tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                    get_utms_message_len, dissect_server_response, conv_data);
            }
            else {
                tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                    get_utms_message_len, dissect_client_request, conv_data);
            }
        }
        else { //utms game server connection handler
            if (pinfo->srcport == DEFAULT_MS_PORT) {
                tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                    get_utms_message_len, dissect_server_response, conv_data);
            }
            else {
                tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                    get_utms_message_len, dissect_client_request, conv_data);
            }
            
        }
        return tvb_captured_length(tvb);
    }

    static int
        dissect_ut_query(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "UT Query");

        int offset = 0;

        guint32 version = 0;
        proto_tree_add_item_ret_uint(tree, utquery_version_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN, &version); offset += sizeof(uint32_t);
        proto_tree_add_item(tree, utquery_type_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);

        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, server_hb_server_id, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_server_address);

            proto_tree_add_item(tree, server_hb_gameport, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_hb_queryport, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);


            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_hostname);
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_level);
            dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_gamegroup);

            proto_tree_add_item(tree, server_hb_submit_numplayers, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_hb_submit_maxplayers, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
            proto_tree_add_item(tree, server_hb_submit_ping, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);



            if (version >= 128) { //UT2004
                proto_tree_add_item(tree, server_hb_submit_flags, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
                dissect_fstring(tvb, pinfo, tree, data, &offset, server_hb_submit_skilllevel);
            }

        }

        //
        return tvb_captured_length(tvb);
    }

    void init_standard_fields(int dissector) {
        proto_register_field_array(dissector, standard_fields_hf, array_length(standard_fields_hf));
    }

    // https://github.com/boundary/wireshark/blob/07eade8124fd1d5386161591b52e177ee6ea849f/epan/dissectors/packet-http.c#L2629
    void
        proto_register_utms(void)
    {
        proto_utms = proto_register_protocol(
            "UT MS",          /* name        */
            "utms",          /* short name  */
            "utms"           /* filter_name */
        );
        init_standard_fields(proto_utms);
        proto_register_subtree_array(list_req_ett, array_length(list_req_ett));


    }

    void
        proto_reg_handoff_utms(void)
    {
        static dissector_handle_t utms_handle;
        static dissector_handle_t utquery_handle;

        utms_handle = create_dissector_handle(dissect_utms, proto_utms);
        dissector_add_uint("tcp.port", DEFAULT_MS_PORT, utms_handle);

        utquery_handle = create_dissector_handle(dissect_ut_query, proto_utms);

        uint16_t query_ports[] = {
            7777,
            7778,
            7788
        };

        for(int i=0;i<sizeof(query_ports) / sizeof(uint16_t); i++) {
            dissector_add_uint("udp.port", query_ports[i], utquery_handle);
        }        
    }




    void plugin_register_utmaster(void)
    {
        static proto_plugin plug;

        plug.register_protoinfo = proto_register_utms;
        plug.register_handoff = proto_reg_handoff_utms; /* or NULL */
        proto_register_plugin(&plug);
    }
