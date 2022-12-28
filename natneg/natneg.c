#include "natneg.h"

int proto_natneg = -1;
gint proto_natneg_ett = -1;

static gint* natneg_etts[] = {
    &proto_natneg_ett
};


//nn core
int natneg_magic_field = -1;
int natneg_version_field = -1;
int natneg_packettype_field = -1;
int natneg_cookie_field = -1;


//nn init
int natneg_init_porttype_field = -1;
int natneg_init_clientindex_field = -1;
int natneg_init_usegameport_field = -1;
int natneg_init_localip_field = -1;
int natneg_init_localport_field = -1;
int natneg_init_gamename = -1;

//nn connect
int natneg_connect_remoteip_field = -1;
int natneg_connect_remoteport_field = -1;
int natneg_connect_gotyourdata_field = -1;
int natneg_connect_finished_field = -1;


static hf_register_info nn_fields_hf[] = {
    { &natneg_magic_field,
        { "magic", "gs_natneg.magic",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_version_field,
        { "version", "gs_natneg.version",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_packettype_field,
        { "packettype ", "gs_natneg.packettype",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_cookie_field,
        { "cookie ", "gs_natneg.cookie",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },

    //nn init
    { &natneg_init_porttype_field,
        { "porttype", "gs_natneg.init.porttype",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_init_clientindex_field,
        { "clientindex", "gs_natneg.init.clientindex",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_init_usegameport_field,
        { "usegameport", "gs_natneg.init.usegameport",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_init_localip_field,
        { "localip", "gs_natneg.init.localip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_init_localport_field,
        { "localport", "gs_natneg.init.localport",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_init_gamename,
        { "gamename ", "gs_natneg.init.gamename",
        FT_STRINGZ, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },

    //nn connect
    { &natneg_connect_remoteip_field,
        { "remoteip", "gs_natneg.connect.remoteip",
        FT_IPv4, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_connect_remoteport_field,
        { "remoteport", "gs_natneg.connect.remoteport",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_connect_gotyourdata_field,
        { "gotyourdata", "gs_natneg.connect.gotyourdata",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &natneg_connect_finished_field,
        { "finished", "gs_natneg.connect.finished",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
};


static gboolean
test_natneg(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    //check minimum natneg length
    if (tvb_captured_length(tvb) < NATNEG_MAGIC_LEN)
        return FALSE;

    //check magic
    if (tvb_get_guint8(tvb, 0) != NN_MAGIC_0)
        return FALSE;
    if (tvb_get_guint8(tvb, 1) != NN_MAGIC_1)
        return FALSE;
    if (tvb_get_guint8(tvb, 2) != NN_MAGIC_2)
        return FALSE;
    if (tvb_get_guint8(tvb, 3) != NN_MAGIC_3)
        return FALSE;
    if (tvb_get_guint8(tvb, 4) != NN_MAGIC_4)
        return FALSE;
    if (tvb_get_guint8(tvb, 5) != NN_MAGIC_5)
        return FALSE;

    return TRUE;
}
static gboolean
dissect_natneg_heur_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{

    if (test_natneg(pinfo, tvb, 0, data)) {
        dissect_natneg(tvb, pinfo, tree, data);
        return TRUE;
    }
    return FALSE;
}

void proto_register_natneg(void)
{
    proto_natneg = proto_register_protocol(
        "GS NatNeg",        /* name        */
        "natneg",          /* short name  */
        "gs_natneg"        /* filter_name */
    );
    proto_register_field_array(proto_natneg, nn_fields_hf, array_length(nn_fields_hf));
    proto_register_subtree_array(natneg_etts, array_length(natneg_etts));
}

void proto_reg_handoff_natneg(void)
{
    static dissector_handle_t natneg_handle;

    natneg_handle = create_dissector_handle(dissect_natneg, proto_natneg);

    heur_dissector_add("udp", dissect_natneg_heur_udp, "GameSpy NatNeg",
        "gs_natneg", proto_natneg, HEURISTIC_ENABLE);
}


void plugin_register_natneg(void) {
    static proto_plugin natneg_plug;

    natneg_plug.register_protoinfo = proto_register_natneg;
    natneg_plug.register_handoff = proto_reg_handoff_natneg;
    proto_register_plugin(&natneg_plug);
}