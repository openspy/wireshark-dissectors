#ifndef _GS_SERVERBROWSING_DISSECTOR_H
#define _GS_SERVERBROWSING_DISSECTOR_H

#include "../main.h"

#define DEFAULT_SBV1_PORT 28900

void plugin_register_serverbrowsing(void);
void proto_register_sbv1(void);
void proto_reg_handoff_sbv1(void);

#endif