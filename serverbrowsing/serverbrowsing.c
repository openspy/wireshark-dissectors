#include "serverbrowsing.h"


void plugin_register_serverbrowsing(void) {
    static proto_plugin serverbrowsing_plug;

    serverbrowsing_plug.register_protoinfo = proto_register_sbv1;
    serverbrowsing_plug.register_handoff = proto_reg_handoff_sbv1;
    proto_register_plugin(&serverbrowsing_plug);
}