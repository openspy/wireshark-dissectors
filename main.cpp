#include "main.h"

#include "serverbrowsing/serverbrowsing.h"
#include "natneg/natneg.h"
#include "peerchat/peerchat.h"
#include "utmaster/main.h"

#include "gslist_keys.h"

const char** gslist_keys_find_by_gamename(const char* name, int len) {
    int i = 0;
    while (true) {
        if (gslist_keys[i][0] == NULL) break;
        if (strncmp(gslist_keys[i][1], name, len) == 0) {
            return (const char**)&gslist_keys[i];
        }
        i++;
    }
    return NULL;
}

int add_string_nts_item(tvbuff_t* tvb, proto_tree* tree, int wireshark_field_id, int offset) {
    int remaining = tvb_reported_length_remaining(tvb, offset);
    gint str_len = tvb_strnlen(tvb, offset, remaining);
    proto_tree_add_item(tree, wireshark_field_id, tvb, offset, str_len + 1, ENC_LITTLE_ENDIAN); offset += str_len + 1;
    return str_len + 1;
}

extern "C" {
    WS_DLL_PUBLIC void plugin_register(void);


    void plugin_register(void)
    {
        plugin_register_natneg();
        plugin_register_peerchat();
        plugin_register_serverbrowsing();
        plugin_register_utmaster();
    }

}