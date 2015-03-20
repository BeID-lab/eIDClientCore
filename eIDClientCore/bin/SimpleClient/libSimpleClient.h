#include <eIDClientCore.h>


void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error);
NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input);

void startSimpleClient(const nPAeIdUserInteractionCallback_t fnUserInteractionCallback_=nPAeIdUserInteractionCallback, const nPAeIdProtocolStateCallback_t fnCurrentStateCallback_ = nPAeIdProtocolStateCallback);
