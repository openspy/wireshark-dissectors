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


#ifndef VERSION
#define VERSION "0.0.1"
#endif

const char** gslist_keys_find_by_gamename(const char* name, int len);
#endif //_MAIN_H
