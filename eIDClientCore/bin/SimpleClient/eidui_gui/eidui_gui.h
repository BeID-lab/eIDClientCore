#ifndef EIDUI_GUI_H
#define EIDUI_GUI_H

#include <eIDClientCore.h>

void nPAeIdProtocolStateCallback_gui(const NPACLIENT_STATE state, const NPACLIENT_ERROR error);
NPACLIENT_ERROR nPAeIdUserInteractionCallback_gui(const SPDescription_t *description, UserInput_t *input);
void nPAeIdCleanup_gui();

#endif