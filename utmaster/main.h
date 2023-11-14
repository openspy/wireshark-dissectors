#ifndef _UTMAIN_H
#define _UTMAIN_H
#define WS_BUILD_DLL
#define HAVE_PLUGINS


#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <stdint.h>

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>

#include <wsutil/wmem/wmem_core.h>

#define DEFAULT_MS_PORT 28902

#ifndef VERSION
#define VERSION "0.0.0"
#endif


//these are always C->S requests (client being UT2004 game(server), server = MS)
enum EClientModeRequest {
	EClientModeRequest_ServerList,
	EClientModeRequest_MOTD
};

enum EServerModeRequest {
	EServerModeRequest_HeartbeatReq, //S->C
	EServerModeRequest_Heartbeat, //C->S
	EServerModeRequest_StatsUpdate,
	EServerModeRequest_InformMatchID = 3,
	//EServerModeRequest_InformNewServer, //??
	EServerModeRequest_PackagesUpdate
};

//from MasterServerClient.uc (IpDrv.u)
enum EQueryType
{
	QT_Equals,
	QT_NotEquals,
	QT_LessThan,
	QT_LessThanEquals,
	QT_GreaterThan,
	QT_GreaterThanEquals,
	QT_Disabled		// if QT_Disabled, query item will not be added
};


typedef struct _utms_request_name_mapping {
	uint8_t request_id;
	uint8_t is_server_mode;
	const char* name;
	const char* response_name;
} utms_request_name_mapping;

typedef struct _utms_pdu_data {
	uint8_t request_id;
	guint32 pdu_id;
} utms_pdu_data;

#define MAX_SERVER_MESSAGES_PER_CONNECTION 50
typedef struct _utms_conv_t {
	guint32	server_challenge_frame; //first packet (from server)
	guint32	client_challenge_response_frame; //second packet (first from client) (CD KEY stuff)
	guint32	server_client_challenge_response_frame; //third packet (second from server) (APPROVED)

	guint32 client_verification_frame;
	guint32 server_verification_response_frame;

	guint32 last_pdu_request_mapping_idx;
	guint32 last_client_request_id;
	struct _utms_pdu_data pdu_request_mapping[MAX_SERVER_MESSAGES_PER_CONNECTION];

	guint32 utms_client_version;
	guint8 utms_is_gameserver; //this is a game server, not client
} utms_conv_t;

extern gint list_req_ett_foo;

extern int proto_utms;

void plugin_register_utmaster(void);

#endif //_MAIN_H
