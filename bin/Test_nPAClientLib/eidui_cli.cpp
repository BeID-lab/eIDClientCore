#include "eidui_cli.h"
#include <eIDClientCore.h>
#include <iomanip>
#include <iostream>
#include <string.h>

#define HEX(x) std::setw(2) << std::setfill('0') << std::hex << (int)(x)

void nPAeIdProtocolStateCallback_ui(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	switch (state) {
		case NPACLIENT_STATE_INITIALIZE:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client successful initialized" << std::endl;

			} else {
				std::cout << "nPA client initialisation failed with code : " << HEX(error) << std::endl;
			}

			break;
		case NPACLIENT_STATE_GOT_PACE_INFO:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client got PACE info successfully" << std::endl;

			} else {
				std::cout << "nPA client got PACE info failed with code : " << HEX(error) << std::endl;
			}

			break;
		case NPACLIENT_STATE_PACE_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client perfomed PACE successfully" << std::endl;

			} else {
				std::cout << "nPA client perform PACE failed with code : " << HEX(error) << std::endl;
			}

			break;
		case NPACLIENT_STATE_TA_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client perfomed TA successfully" << std::endl;

			} else {
				std::cout << "nPA client perform TA failed with code : " << error << std::endl;
			}

			break;
		case NPACLIENT_STATE_CA_PERFORMED:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client perfomed CA successfully" << std::endl;

			} else {
				std::cout << "nPA client perform CA failed with code : " << HEX(error) << std::endl;
			}

			break;
		case NPACLIENT_STATE_READ_ATTRIBUTES:

			if (error == NPACLIENT_ERROR_SUCCESS) {
				std::cout << "nPA client read attribute successfully" << std::endl;

			} else {
				std::cout << "nPA client read attributes failed with code : " << HEX(error) << std::endl;
			}

			break;
		default:
			break;
	}

}

NPACLIENT_ERROR nPAeIdUserInteractionCallback_ui(
	const SPDescription_t *description, UserInput_t *input)
{
	std::cout << "serviceName: ";
	std::cout.write((char *) description->name.pDataBuffer, description->name.bufferSize);
	std::cout << std::endl;
	std::cout << "serviceURL:  ";
	std::cout.write((char *) description->url.pDataBuffer, description->url.bufferSize);
	std::cout << std::endl;
	std::cout << "certificateDescription:" << std::endl;
	std::cout.write((char *) description->description.pDataBuffer, description->description.bufferSize);
	std::cout << std::endl;

	switch (description->chat_required.type) {
		case TT_IS:
			std::cout << "Inspection System:" << std::endl;
			if (description->chat_required.authorization.is.read_finger 	) std::cout << "\tRead Fingerprint" << std::endl;
			if (description->chat_required.authorization.is.read_iris  	) std::cout << "\tRead Iris" << std::endl;
			if (description->chat_required.authorization.is.read_eid		) std::cout << "\tRead eID" << std::endl;
			break;

		case TT_AT:
			std::cout << "Authentication Terminal:" << std::endl;
			if (description->chat_required.authorization.at.age_verification 				) std::cout << "\tVerify Age" << std::endl;
			if (description->chat_required.authorization.at.community_id_verification 		) std::cout << "\tVerify Community ID" << std::endl;
			if (description->chat_required.authorization.at.restricted_id 					) std::cout << "\tRestricted ID" << std::endl;
			if (description->chat_required.authorization.at.privileged 					) std::cout << "\tPrivileged Terminal" << std::endl;
			if (description->chat_required.authorization.at.can_allowed 					) std::cout << "\tCAN allowed" << std::endl;
			if (description->chat_required.authorization.at.pin_management 				) std::cout << "\tPIN Management" << std::endl;
			if (description->chat_required.authorization.at.install_cert 					) std::cout << "\tInstall Certificate" << std::endl;
			if (description->chat_required.authorization.at.install_qualified_cert 		) std::cout << "\tInstall Qualified Certificate" << std::endl;
			if (description->chat_required.authorization.at.read_dg1         				) std::cout << "\tRead Document Type" << std::endl;
			if (description->chat_required.authorization.at.read_dg2                  		) std::cout << "\tRead Issuing State" << std::endl;
			if (description->chat_required.authorization.at.read_dg3      					) std::cout << "\tRead Date of Expiry" << std::endl;
			if (description->chat_required.authorization.at.read_dg4 						) std::cout << "\tRead Given Names" << std::endl;
			if (description->chat_required.authorization.at.read_dg5 						) std::cout << "\tRead Family Names" << std::endl;
			if (description->chat_required.authorization.at.read_dg6 						) std::cout << "\tRead Religious/Artistic Name" << std::endl;
			if (description->chat_required.authorization.at.read_dg7 						) std::cout << "\tRead Academic Title" << std::endl;
			if (description->chat_required.authorization.at.read_dg8 						) std::cout << "\tRead Date of Birth" << std::endl;
			if (description->chat_required.authorization.at.read_dg9        				) std::cout << "\tRead Place of Birth" << std::endl;
			if (description->chat_required.authorization.at.read_dg10                		) std::cout << "\tRead Nationality" << std::endl;
			if (description->chat_required.authorization.at.read_dg11     					) std::cout << "\tRead Sex" << std::endl;
			if (description->chat_required.authorization.at.read_dg12						) std::cout << "\tRead OptionalDataR" << std::endl;
			if (description->chat_required.authorization.at.read_dg13						) std::cout << "\tRead DG 13" << std::endl;
			if (description->chat_required.authorization.at.read_dg14						) std::cout << "\tRead DG 14" << std::endl;
			if (description->chat_required.authorization.at.read_dg15						) std::cout << "\tRead DG 15" << std::endl;
			if (description->chat_required.authorization.at.read_dg16						) std::cout << "\tRead DG 16" << std::endl;
			if (description->chat_required.authorization.at.read_dg17        				) std::cout << "\tRead Normal Place of Residence" << std::endl;
			if (description->chat_required.authorization.at.read_dg18             			) std::cout << "\tRead Community ID" << std::endl;
			if (description->chat_required.authorization.at.read_dg19     					) std::cout << "\tRead Residence Permit I" << std::endl;
			if (description->chat_required.authorization.at.read_dg20						) std::cout << "\tRead Residence Permit II" << std::endl;
			if (description->chat_required.authorization.at.read_dg21						) std::cout << "\tRead OptionalDataRW" << std::endl;
			if (description->chat_required.authorization.at.write_dg21						) std::cout << "\tWrite OptionalDataRW" << std::endl;
			if (description->chat_required.authorization.at.write_dg20        				) std::cout << "\tWrite Residence Permit I" << std::endl;
			if (description->chat_required.authorization.at.write_dg19                		) std::cout << "\tWrite Residence Permit II" << std::endl;
			if (description->chat_required.authorization.at.write_dg18    					) std::cout << "\tWrite Community ID" << std::endl;
			if (description->chat_required.authorization.at.write_dg17						) std::cout << "\tWrite Normal Place of Residence" << std::endl;
			break;

		case TT_ST:
			std::cout << "Signature Terminal:" << std::endl;
			if (description->chat_required.authorization.st.generate_signature 			)     std::cout << "\tGenerate electronic signature" << std::endl;
			if (description->chat_required.authorization.st.generate_qualified_signature 	) std::cout << "\tGenerate qualified electronic signature" << std::endl;
			break;

		default:
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	input->chat_selected = description->chat_required;

	return NPACLIENT_ERROR_SUCCESS;
}
