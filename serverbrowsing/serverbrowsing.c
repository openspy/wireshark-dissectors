#include "serverbrowsing.h"


void plugin_register_serverbrowsing(void) {
    static proto_plugin serverbrowsing_plug_v1;

    serverbrowsing_plug_v1.register_protoinfo = proto_register_sbv1;
    serverbrowsing_plug_v1.register_handoff = proto_reg_handoff_sbv1;
    proto_register_plugin(&serverbrowsing_plug_v1);

    static proto_plugin serverbrowsing_plug_v2;

    serverbrowsing_plug_v2.register_protoinfo = proto_register_sbv2;
    serverbrowsing_plug_v2.register_handoff = proto_reg_handoff_sbv2;
    proto_register_plugin(&serverbrowsing_plug_v2);
}