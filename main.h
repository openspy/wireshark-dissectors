#ifndef _MAIN_H
#define _MAIN_H
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


#ifndef VERSION
#define VERSION "0.0.1"
#endif

const char** gslist_keys_find_by_gamename(const char* name, int len);
void show_dump(int left, unsigned char *data, unsigned int len, FILE *stream);
int add_string_nts_item(tvbuff_t* tvb, proto_tree* tree, int wireshark_field_id, int offset);
#endif //_MAIN_H
