#ifndef _EIDUI_CLI_H
#define _EIDUI_CLI_H
#if defined(__cplusplus)
extern "C"
{
#endif

#include <eIDClientCore.h>

void nPAeIdProtocolStateCallback_ui(const NPACLIENT_STATE state, const NPACLIENT_ERROR error);
NPACLIENT_ERROR nPAeIdUserInteractionCallback_ui(const SPDescription_t *description, UserInput_t *input);

#if defined(__cplusplus)
}
#endif
#endif
