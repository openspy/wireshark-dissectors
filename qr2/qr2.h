#ifndef _QR2_H
#define _QR2_H
#include "../main.h"

#define QR2_PORT 27900

#define QR_MAGIC_1 0xFE
#define QR_MAGIC_2 0xFD
#define QR_MAGIC_LEN 2

#define PACKET_QUERY              0x00
#define PACKET_CHALLENGE          0x01
#define PACKET_ECHO               0x02
#define PACKET_ECHO_RESPONSE      0x05  // 0x05, not 0x03 (order)
#define PACKET_HEARTBEAT          0x03
#define PACKET_ADDERROR           0x04
#define PACKET_CLIENT_MESSAGE     0x06
#define PACKET_CLIENT_MESSAGE_ACK 0x07
#define PACKET_KEEPALIVE          0x08
#define PACKET_PREQUERY_IP_VERIFY 0x09
#define PACKET_AVAILABLE          0x09
#define PACKET_CLIENT_REGISTERED  0x0A

extern int proto_qr2;
extern gint proto_qr2_ett;

extern int qr2_magic_field;
extern int qr2_msgid_field;
extern int qr2_instance_key_field;
extern int qr2_msgid_name;

void plugin_register_qr2(void);
int dissect_qr2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
#endif //_QR2_H