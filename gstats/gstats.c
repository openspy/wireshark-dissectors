#include "gstats.h"
#include "xorenc.h"

int proto_gstats = -1;

void plugin_register_gstats(void)
{
    static proto_plugin gstats_plug;

    gstats_plug.register_protoinfo = proto_register_gstats;
    gstats_plug.register_handoff = proto_reg_handoff_gstats;
    proto_register_plugin(&gstats_plug);
}

void proto_reg_handoff_gstats(void)
{
    static dissector_handle_t gstats_handle;

    gstats_handle = create_dissector_handle(dissect_gstats, proto_gstats);
    dissector_add_uint("tcp.port", DEFAULT_GSTATS_PORT, gstats_handle);
}

void proto_register_gstats(void)
{
    proto_gstats = proto_register_protocol(
        "GS GameStatus", /* name        */
        "gstats",        /* short name  */
        "gs_gstats"      /* filter_name */
    );
    proto_register_field_array(proto_natneg, nn_fields_hf, array_length(nn_fields_hf));
    proto_register_subtree_array(natneg_etts, array_length(natneg_etts));
}

int dissect_gstats(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    // here is the process of the gamespy network request game response?
    // char[] decrypted_data =
    guint16 decrypted_length = tvb_captured_length_remaining(tvb, 0); // no padding in peerchat, its just the packet length
    guchar *decrypted_heap_buffer = (guchar *)tvb_memdup(pinfo->pool, tvb, 0, decrypted_length);

    // decrypt the raw message with xor encoding
    xcode_buf(decrypted_heap_buffer, decrypted_length);

    tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, decrypted_heap_buffer, decrypted_length, decrypted_length);

    add_new_data_source(pinfo, decrypted_tvb, "Decrypted Data");
    // then it is finished?
}
