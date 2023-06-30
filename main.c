#include "main.h"

#include "natneg/natneg.h"
#include "peerchat/peerchat.h"
#include "ut2004/main.h"

#include "gslist_keys.h"

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);


void plugin_register(void)
{
    plugin_register_natneg();
    plugin_register_peerchat();
    plugin_register_serverbrowsing();
    plugin_register_ut2004();
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

int add_string_nts_item(tvbuff_t* tvb, proto_tree* tree, int wireshark_field_id, int offset) {
   // int remaining = tvb_captured_length_remaining(tvb, offset);
   // char *string_buffer = (char *)tvb_get_ptr(tvb, offset, remaining);
   // int slen = strlen(string_buffer) + 1;
   // proto_tree_add_item(tree, wireshark_field_id, tvb, offset, slen, ENC_LITTLE_ENDIAN); offset += slen;
    int remaining = tvb_reported_length_remaining(tvb, offset);
    gint str_len = tvb_strnlen(tvb, offset, remaining);
    proto_tree_add_item(tree, wireshark_field_id, tvb, offset, str_len + 1, ENC_LITTLE_ENDIAN); offset += str_len + 1;
    //guint8 *string = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len, ENC_ASCII);
    return str_len + 1;
}