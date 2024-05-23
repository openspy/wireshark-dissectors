#include "qr2.h"

int dissect_qr2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{

    proto_item* ti = proto_tree_add_item(tree, proto_qr2, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, proto_qr2_ett);

    int offset = 0;
    guint32 nn_version;
    guint32 nn_packettype;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GS QR2");

    if(pinfo->srcport == QR2_PORT) {
        proto_tree_add_item(tree, qr2_magic_field, tvb, offset, QR_MAGIC_LEN, ENC_LITTLE_ENDIAN); offset += QR_MAGIC_LEN;
    }

    //
    guint32 msgid;
    proto_tree_add_item_ret_uint(tree, qr2_msgid_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &msgid);
    switch(msgid) {
        case PACKET_CHALLENGE:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_CHALLENGE");
        break;
        case PACKET_ECHO:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_ECHO");
        break;
        case PACKET_ECHO_RESPONSE:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_ECHO_RESPONSE");
        break;
        case PACKET_HEARTBEAT:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_HEARTBEAT");
        break;
        case PACKET_ADDERROR:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_ADDERROR");
        break;
        case PACKET_CLIENT_MESSAGE:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_CLIENT_MESSAGE");
        break;
        case PACKET_CLIENT_MESSAGE_ACK:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_CLIENT_MESSAGE_ACK");
        break;
        case PACKET_KEEPALIVE:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_KEEPALIVE");
        break;
        case PACKET_AVAILABLE:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_AVAILABLE");
        break;
        case PACKET_CLIENT_REGISTERED:
        proto_tree_add_string(tree, qr2_msgid_name, tvb, offset - 1, sizeof(uint8_t), "PACKET_CLIENT_REGISTERED");
        break;
    }
    offset += sizeof(uint8_t);

    proto_tree_add_item(tree, qr2_instance_key_field, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN); offset += sizeof(uint32_t);
    

    return tvb_captured_length(tvb);
}