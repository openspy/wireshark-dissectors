#ifndef _GS_NATNEG_DISSECTOR_H
#define _GS_NATNEG_DISSECTOR_H

#include "../main.h"

#define DEFAULT_NATNEG_PORT 27901

#define NATNEG_MAGIC_LEN 6
#define NN_MAGIC_0 0xFD
#define NN_MAGIC_1 0xFC
#define NN_MAGIC_2 0x1E
#define NN_MAGIC_3 0x66
#define NN_MAGIC_4 0x6A
#define NN_MAGIC_5 0xB2

#define NN_INIT	0
#define NN_INITACK 1
#define NN_ERTTEST 2
#define NN_ERTACK 3
#define NN_STATEUPDATE 4
#define NN_CONNECT 5
#define NN_CONNECT_ACK 6
#define NN_CONNECT_PING 7
#define NN_BACKUP_TEST 8
#define NN_BACKUP_ACK 9
#define NN_ADDRESS_CHECK 10
#define NN_ADDRESS_REPLY 11
#define NN_NATIFY_REQUEST 12
#define NN_REPORT 13
#define NN_REPORT_ACK 14
#define NN_PREINIT 15
#define NN_PREINIT_ACK 16


extern int proto_natneg;
extern gint proto_natneg_ett;

extern int natneg_magic_field;
extern int natneg_version_field;
extern int natneg_packettype_field;
extern int natneg_cookie_field;

//nn init
extern int natneg_init_porttype_field;
extern int natneg_init_clientindex_field;
extern int natneg_init_usegameport_field;
extern int natneg_init_localip_field;
extern int natneg_init_localport_field;

//nn connect
extern int natneg_connect_remoteip_field;
extern int natneg_connect_remoteport_field;
extern int natneg_connect_gotyourdata_field;
extern int natneg_connect_finished_field;

void plugin_register_natneg(void);

int dissect_natneg(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);
#endif //_GS_NATNEG_DISSECTOR_H