#include "qr2.h"

int proto_qr2 = -1;
gint proto_qr2_ett = -1;

static gint* qr2_etts[] = {
    &proto_qr2_ett
};


//nn core
int qr2_magic_field = -1;
int qr2_msgid_field = -1;
int qr2_instance_key_field = -1;
int qr2_msgid_name = -1;

static hf_register_info qr2_fields_hf[] = {
    { &qr2_magic_field,
        { "magic", "gs_qr2.magic",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &qr2_msgid_field,
        { "msgid", "gs_qr2.msgid",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &qr2_msgid_name,
        { "msg_name", "gs_qr2.msg_name",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &qr2_instance_key_field,
        { "instance_key", "gs_qr2.instance_key",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
};


static gboolean
test_qr2(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    //check minimum natneg length
    if (tvb_captured_length(tvb) < 2)
        return FALSE;

    if(pinfo->destport == QR2_PORT) {
        if (tvb_captured_length(tvb) < 5) //msgid + instance key
            return FALSE;
        guint8 msgid = tvb_get_guint8(tvb, 0);

        if(msgid > 0x0A) {
            return FALSE;
        }
        return TRUE;
    } else if(pinfo->srcport == QR2_PORT) {
        //check magic
        if (tvb_get_guint8(tvb, 0) != QR_MAGIC_1)
            return FALSE;
        if (tvb_get_guint8(tvb, 1) != QR_MAGIC_2)
            return FALSE;
        return TRUE;
    }



    return FALSE;
}
static gboolean
dissect_qr2_heur_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{

    if (test_qr2(pinfo, tvb, 0, data)) {
        dissect_qr2(tvb, pinfo, tree, data);
        return TRUE;
    }
    return FALSE;
}

void proto_register_qr2(void)
{
    proto_qr2 = proto_register_protocol(
        "GS QR2",        /* name        */
        "qr2",          /* short name  */
        "gs_qr2"        /* filter_name */
    );
    proto_register_field_array(proto_qr2, qr2_fields_hf, array_length(qr2_fields_hf));
    proto_register_subtree_array(qr2_etts, array_length(qr2_etts));
}

void proto_reg_handoff_qr2(void)
{
    static dissector_handle_t qr2_handle;

    qr2_handle = create_dissector_handle(dissect_qr2, proto_qr2);

    heur_dissector_add("udp", (heur_dissector_t)dissect_qr2_heur_udp, "GameSpy QR2",
        "gs_qr2", proto_qr2, HEURISTIC_ENABLE);
}


void plugin_register_qr2(void) {
    static proto_plugin qr2_plug;

    qr2_plug.register_protoinfo = proto_register_qr2;
    qr2_plug.register_handoff = proto_reg_handoff_qr2;
    proto_register_plugin(&qr2_plug);
}