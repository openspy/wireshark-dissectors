#ifndef _GS_SERVERBROWSING_DISSECTOR_H
#define _GS_SERVERBROWSING_DISSECTOR_H

#include "../main.h"

#define DEFAULT_SBV1_PORT 28900
#define DEFAULT_SBV2_PORT 28910

//sbv2 stuff

#define KEYTYPE_STRING	0
#define KEYTYPE_BYTE	1
#define KEYTYPE_SHORT	2

//message types for outgoing requests
#define SERVER_LIST_REQUEST		0
#define SERVER_INFO_REQUEST		1
#define SEND_MESSAGE_REQUEST	2
#define KEEPALIVE_REPLY			3
#define MAPLOOP_REQUEST			4
#define PLAYERSEARCH_REQUEST	5

//message types for incoming requests
#define PUSH_KEYS_MESSAGE		1
#define PUSH_SERVER_MESSAGE		2
#define KEEPALIVE_MESSAGE		3
#define DELETE_SERVER_MESSAGE	4
#define MAPLOOP_MESSAGE			5
#define PLAYERSEARCH_MESSAGE	6

//server list update options
#define SEND_FIELDS_FOR_ALL		1
#define NO_SERVER_LIST			2
#define PUSH_UPDATES			4
#define SEND_GROUPS				32
#define NO_LIST_CACHE			64
#define LIMIT_RESULT_COUNT		128

#define ALTERNATE_SOURCE_IP 8


#define CRYPTCHAL_LEN 10
#define SERVCHAL_LEN 25
#define LIST_CHALLENGE_LEN 8


//game server flags
#define UNSOLICITED_UDP_FLAG	1
#define PRIVATE_IP_FLAG			2
#define CONNECT_NEGOTIATE_FLAG	4
#define ICMP_IP_FLAG			8
#define NONSTANDARD_PORT_FLAG	16
#define NONSTANDARD_PRIVATE_PORT_FLAG	32
#define HAS_KEYS_FLAG					64
#define HAS_FULL_RULES_FLAG				128

//

void plugin_register_serverbrowsing(void);
void proto_register_sbv1(void);
void proto_reg_handoff_sbv1(void);

void proto_register_sbv2(void);
void proto_reg_handoff_sbv2(void);

#endif