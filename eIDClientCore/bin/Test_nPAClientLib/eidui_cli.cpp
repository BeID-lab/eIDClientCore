#include "eidui_cli.h"
#include <eIDClientCore.h>
#include <iomanip>
#include <cstring>
#if _MSC_VER
#define snprintf _snprintf
#endif

#define HEX(x) std::setw(2) << std::setfill('0') << std::hex << (int)(x)

void nPAeIdProtocolStateCallback_ui(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	switch (state) {
		case NPACLIENT_STATE_INITIALIZE:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client successful initialized\n");

			} else {
				printf("nPA client initialisation failed with code : %08lX\n", error);
			}

			break;
		case NPACLIENT_STATE_GOT_PACE_INFO:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client got PACE info successfully\n");

			} else {
				printf("nPA client got PACE info failed with code : %08lX\n", error);
			}

			break;
		case NPACLIENT_STATE_PACE_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client perfomed PACE successfully\n");

			} else {
				printf("nPA client perform PACE failed with code : %08lX\n", error);
			}

			break;
		case NPACLIENT_STATE_TA_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client perfomed TA successfully\n");

			} else {
				printf("nPA client perform TA failed with code : %08lX\n", error);
			}

			break;
		case NPACLIENT_STATE_CA_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client perfomed CA successfully\n");

			} else {
				printf("nPA client perform CA failed with code : %08lX\n", error);
			}

			break;
		case NPACLIENT_STATE_READ_ATTRIBUTES:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				printf("nPA client read attribute successfully\n");

			} else {
				printf("nPA client read attributes failed with code : %08lX\n", error);
			}

			break;
		default:
			break;
	}

}

#define MAX(a,b) (a>b ? a : b)
NPACLIENT_ERROR nPAeIdUserInteractionCallback_ui(
	const SPDescription_t *description, UserInput_t *input)
{
	char buf[1024];
	snprintf(buf, MAX(sizeof buf, description->name.bufferSize), (char *) description->name.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';
	printf("serviceName: %s\n", buf);
	snprintf(buf, MAX(sizeof buf, description->url.bufferSize), (char *) description->url.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';
	printf("serviceURL:  %s\n", buf);
	snprintf(buf, MAX(sizeof buf, description->description.bufferSize), (char *) description->description.pDataBuffer);
	buf[(sizeof buf) - 1] = '\0';
	printf("certificateDescription:\n%s\n", buf);
	if(description->transactionInfo.bufferSize > 0)
	{
		snprintf(buf, MAX(sizeof buf, description->transactionInfo.bufferSize), (char *) description->transactionInfo.pDataBuffer);
		buf[(sizeof buf) - 1] = '\0';
		printf("TransactionInfo:\n%s\n", buf);
	}
	if(description->transactionInfoHidden.bufferSize > 0)
	{
		snprintf(buf, MAX(sizeof buf, description->transactionInfoHidden.bufferSize), (char *) description->transactionInfoHidden.pDataBuffer);
		buf[(sizeof buf) - 1] = '\0';
		printf("TransactionInfoHidden:\n%s\n", buf);
	}

	switch (description->chat_required.type) {
		case TT_IS:
			printf("Inspection System:\n");
			if (description->chat_required.authorization.is.read_finger 	) printf("\tRead Fingerprint\n");
			if (description->chat_required.authorization.is.read_iris  		) printf("\tRead Iris\n");
			if (description->chat_required.authorization.is.read_eid		) printf("\tRead eID\n");
			break;

		case TT_AT:
			printf("Authentication Terminal:\n");
			if (description->chat_required.authorization.at.age_verification 				) printf("\tVerify Age\n");
			if (description->chat_required.authorization.at.community_id_verification 		) printf("\tVerify Community ID\n");
			if (description->chat_required.authorization.at.restricted_id 					) printf("\tRestricted ID\n");
			if (description->chat_required.authorization.at.privileged 						) printf("\tPrivileged Terminal\n");
			if (description->chat_required.authorization.at.can_allowed 					) printf("\tCAN allowed\n");
			if (description->chat_required.authorization.at.pin_management 					) printf("\tPIN Management\n");
			if (description->chat_required.authorization.at.install_cert 					) printf("\tInstall Certificate\n");
			if (description->chat_required.authorization.at.install_qualified_cert 			) printf("\tInstall Qualified Certificate\n");
			if (description->chat_required.authorization.at.read_dg1         				) printf("\tRead Document Type\n");
			if (description->chat_required.authorization.at.read_dg2                  		) printf("\tRead Issuing State\n");
			if (description->chat_required.authorization.at.read_dg3      					) printf("\tRead Date of Expiry\n");
			if (description->chat_required.authorization.at.read_dg4 						) printf("\tRead Given Names\n");
			if (description->chat_required.authorization.at.read_dg5 						) printf("\tRead Family Names\n");
			if (description->chat_required.authorization.at.read_dg6 						) printf("\tRead Religious/Artistic Name\n");
			if (description->chat_required.authorization.at.read_dg7 						) printf("\tRead Academic Title\n");
			if (description->chat_required.authorization.at.read_dg8 						) printf("\tRead Date of Birth\n");
			if (description->chat_required.authorization.at.read_dg9        				) printf("\tRead Place of Birth\n");
			if (description->chat_required.authorization.at.read_dg10                		) printf("\tRead Nationality\n");
			if (description->chat_required.authorization.at.read_dg11     					) printf("\tRead Sex\n");
			if (description->chat_required.authorization.at.read_dg12						) printf("\tRead OptionalDataR\n");
			if (description->chat_required.authorization.at.read_dg13						) printf("\tRead DG 13\n");
			if (description->chat_required.authorization.at.read_dg14						) printf("\tRead DG 14\n");
			if (description->chat_required.authorization.at.read_dg15						) printf("\tRead DG 15\n");
			if (description->chat_required.authorization.at.read_dg16						) printf("\tRead DG 16\n");
			if (description->chat_required.authorization.at.read_dg17        				) printf("\tRead Normal Place of Residence\n");
			if (description->chat_required.authorization.at.read_dg18             			) printf("\tRead Community ID\n");
			if (description->chat_required.authorization.at.read_dg19     					) printf("\tRead Residence Permit I\n");
			if (description->chat_required.authorization.at.read_dg20						) printf("\tRead Residence Permit II\n");
			if (description->chat_required.authorization.at.read_dg21						) printf("\tRead OptionalDataRW\n");
			if (description->chat_required.authorization.at.write_dg21						) printf("\tWrite OptionalDataRW\n");
			if (description->chat_required.authorization.at.write_dg20        				) printf("\tWrite Residence Permit I\n");
			if (description->chat_required.authorization.at.write_dg19                		) printf("\tWrite Residence Permit II\n");
			if (description->chat_required.authorization.at.write_dg18    					) printf("\tWrite Community ID\n");
			if (description->chat_required.authorization.at.write_dg17						) printf("\tWrite Normal Place of Residence\n");
			break;

		case TT_ST:
			printf("Signature Terminal:\n");
			if (description->chat_required.authorization.st.generate_signature 				) printf("\tGenerate electronic signature\n");
			if (description->chat_required.authorization.st.generate_qualified_signature 	) printf("\tGenerate qualified electronic signature\n");
			break;

		default:
			printf("%s:%d: Error\n", __FILE__, __LINE__);
	}

	input->chat_selected = description->chat_required;

	return NPACLIENT_ERROR_SUCCESS;
}

void nPAeIdCleanup_ui()
{
}
