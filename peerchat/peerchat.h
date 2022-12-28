#ifndef _GS_PEERCHAT_DISSECTOR_H
#define _GS_PEERCHAT_DISSECTOR_H

#include "../main.h"

#define DEFAULT_PEERCHAT_PORT 6667
#define PEERCHAT_CHALLENGE_LEN 16


typedef struct {
	unsigned char   gs_peerchat_1;
	unsigned char   gs_peerchat_2;
	unsigned char   gs_peerchat_crypt[256];
} gs_peerchat_ctx;


typedef struct _peerchat_conv_t {
	guint32	crypt_frame;
	guint32	challenge_frame;

	const char** game_info; //pointer to gslist_keys

	char client_challenge[PEERCHAT_CHALLENGE_LEN];
	char server_challenge[PEERCHAT_CHALLENGE_LEN];

	int challenge_setup;

	int last_client_pdu;
	gs_peerchat_ctx client_ctx;
	int last_server_pdu;
	gs_peerchat_ctx server_ctx;
	
} peerchat_conv_t;

typedef struct _peerchat_pdu_crypto_state {
	gs_peerchat_ctx state;
} peerchat_pdu_crypto_state;

void plugin_register_peerchat(void);
int dissect_peerchat(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);

#endif //_GS_PEERCHAT_DISSECTOR_H