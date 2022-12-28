#include "natneg.h"
int dissect_natneg_init(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset, int do_read_gamename) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NN Init");
    proto_tree_add_item(tree, natneg_init_porttype_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, natneg_init_clientindex_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, natneg_init_usegameport_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, natneg_init_localip_field, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    proto_tree_add_item(tree, natneg_init_localport_field, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);


    if (do_read_gamename) {
        int remaining = tvb_captured_length_remaining(tvb, offset);
        proto_tree_add_item(tree, natneg_init_gamename, tvb, offset, remaining, ENC_BIG_ENDIAN);
    }
    
    return tvb_captured_length(tvb);

}
int dissect_natneg_init_ack(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    int result = dissect_natneg_init(tvb, pinfo, tree, data, offset, 0);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NN Init Ack");
    return result;
}

int dissect_natneg_connect(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NN Connect");
    proto_tree_add_item(tree, natneg_connect_remoteip_field, tvb, offset, sizeof(uint32_t), ENC_BIG_ENDIAN); offset += sizeof(uint32_t);
    proto_tree_add_item(tree, natneg_connect_remoteport_field, tvb, offset, sizeof(uint16_t), ENC_BIG_ENDIAN); offset += sizeof(uint16_t);
    proto_tree_add_item(tree, natneg_connect_gotyourdata_field, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, natneg_connect_finished_field, tvb, offset, sizeof(uint8_t), ENC_BIG_ENDIAN); offset += sizeof(uint8_t);
    return tvb_captured_length(tvb);
}
int dissect_natneg_connect_ack(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    int result = dissect_natneg_connect(tvb, pinfo, tree, data, offset);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NN Connect Ack");
    return result;
}

int dissect_natneg_connect_ping(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int offset) {
    int result = dissect_natneg_connect(tvb, pinfo, tree, data, offset);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NN Connect Ping");
    return result;
}

int dissect_natneg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{


    proto_item* ti = proto_tree_add_item(tree, proto_natneg, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, proto_natneg_ett);

    int offset = 0;
    guint32 nn_version;
    guint32 nn_packettype;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GS NatNeg");

    proto_tree_add_item(tree, natneg_magic_field, tvb, offset, NATNEG_MAGIC_LEN, ENC_LITTLE_ENDIAN); offset += NATNEG_MAGIC_LEN;
    proto_tree_add_item_ret_uint(tree, natneg_version_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &nn_version); offset += sizeof(uint8_t);
    proto_tree_add_item_ret_uint(tree, natneg_packettype_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &nn_packettype); offset += sizeof(uint8_t);
    proto_tree_add_item(tree, natneg_cookie_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);

    int do_read_gamename = nn_version > 1;

    switch (nn_packettype) {
        case NN_INIT:
            return dissect_natneg_init(tvb, pinfo, tree, data, offset, do_read_gamename);
            break;
        case NN_INITACK:
            return dissect_natneg_init_ack(tvb, pinfo, tree, data, offset);
            break;
        case NN_ERTTEST:
            break;
        case NN_ERTACK:
            break;
        case NN_STATEUPDATE:
            break;
        case NN_CONNECT:
            return dissect_natneg_connect(tvb, pinfo, tree, data, offset);
            break;
        case NN_CONNECT_ACK:
            return dissect_natneg_connect_ack(tvb, pinfo, tree, data, offset);
            break;
        case NN_CONNECT_PING:
            return dissect_natneg_connect_ping(tvb, pinfo, tree, data, offset);
            break;
        case NN_BACKUP_TEST:
            break;
        case NN_BACKUP_ACK:
            break;
        case NN_ADDRESS_CHECK:
            break;
        case NN_ADDRESS_REPLY:
            break;
        case NN_NATIFY_REQUEST:
            break;
        case NN_REPORT:
            break;
        case NN_REPORT_ACK:
            break;
        case NN_PREINIT:
            break;
        case NN_PREINIT_ACK:
            break;
    }

    return tvb_captured_length(tvb);
}