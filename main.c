#include "main.h"

#include "natneg/natneg.h"
#include "peerchat/peerchat.h"

#include "gslist_keys.h"

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);


void plugin_register(void)
{
    plugin_register_natneg();
    plugin_register_peerchat();
}

const char** gslist_keys_find_by_gamename(const char* name, int len) {
    int i = 0;
    while(true) {
        if (gslist_keys[i][0] == NULL) break;
        if (strncmp(gslist_keys[i][1], name, len) == 0) {
            return &gslist_keys[i];
        }
        i++;
    }
    return NULL;
}