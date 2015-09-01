/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "eIDClientCore.h"
#include "eIDECardClientPAOS.h"

#include <EstablishPACEChannelInput.h>
#include <EstablishPACEChannelOutput.h>
#include <SecurityInfos.h>              // ef.CardAccess
#include <CertificateDescription.h>
#include <PlainTermsOfUsage.h>
#include <CertificateBody.h>
#include <CVCertificate.h>
#include <eIDOID.h>
#include <eIDHelper.h>

#include "../crypto.h"

#include "eIDUtils.h"
using namespace Bundesdruckerei::eIDUtils;

#include "eCardCore/eCardStatus.h"
#include "eCardCore/eIdClientCardReader.h"
#include "nPA-EAC/nPACard.h"

#ifndef DISABLE_PCSC
#include "eCardCore/PCSCManager.h"
#endif
#ifndef DISABLE_EXTERNAL
#include "eCardCore/ExternalManager.h"
#endif

#include <map>
#include <list>
#include <vector>
#include <cstring>

#include <debug.h>
#include <testing.h>

#include "eCardCore/ICard.h"
#include "nPA-EAC/nPAAPI.h"

typedef std::list<std::string>  certificateList_t;

bool decode_CertificateHolderAuthorizationTemplate_t(const CertificateHolderAuthorizationTemplate_t &chat_in, struct chat &chat_out)
{
	OBJECT_IDENTIFIER_t is = makeOID(id_IS);
	OBJECT_IDENTIFIER_t at = makeOID(id_AT);
	OBJECT_IDENTIFIER_t st = makeOID(id_ST);
	bool r = false;
    
	if (chat_in.authTerminalID == is) {
		if (chat_in.chat.size != 1) {
			goto err;
		}
        
		chat_out.type = TT_IS;
		chat_out.authorization.is.read_finger       		= chat_in.chat.buf[0] & 0x01 ? 1 : 0;
		chat_out.authorization.is.read_iris               	= chat_in.chat.buf[0] & 0x02 ? 1 : 0;
		chat_out.authorization.is.RFU1     					= chat_in.chat.buf[0] & 0x04 ? 1 : 0;
		chat_out.authorization.is.RFU2						= chat_in.chat.buf[0] & 0x08 ? 1 : 0;
		chat_out.authorization.is.RFU3						= chat_in.chat.buf[0] & 0x10 ? 1 : 0;
		chat_out.authorization.is.read_eid					= chat_in.chat.buf[0] & 0x20 ? 1 : 0;
		chat_out.authorization.is.role						= chat_in.chat.buf[0] >> 5;
	} else if (chat_in.authTerminalID == at) {
		if (chat_in.chat.size != 5) {
			goto err;
		}
        
		chat_out.type = TT_AT;
		chat_out.authorization.at.age_verification 			= chat_in.chat.buf[4] & 0x01 ? 1 : 0;
		chat_out.authorization.at.community_id_verification	= chat_in.chat.buf[4] & 0x02 ? 1 : 0;
		chat_out.authorization.at.restricted_id 			= chat_in.chat.buf[4] & 0x04 ? 1 : 0;
		chat_out.authorization.at.privileged 				= chat_in.chat.buf[4] & 0x08 ? 1 : 0;
		chat_out.authorization.at.can_allowed 				= chat_in.chat.buf[4] & 0x10 ? 1 : 0;
		chat_out.authorization.at.pin_management 			= chat_in.chat.buf[4] & 0x20 ? 1 : 0;
		chat_out.authorization.at.install_cert 				= chat_in.chat.buf[4] & 0x40 ? 1 : 0;
		chat_out.authorization.at.install_qualified_cert 	= chat_in.chat.buf[4] & 0x80 ? 1 : 0;
		chat_out.authorization.at.read_dg1         			= chat_in.chat.buf[3] & 0x01 ? 1 : 0;
		chat_out.authorization.at.read_dg2                 	= chat_in.chat.buf[3] & 0x02 ? 1 : 0;
		chat_out.authorization.at.read_dg3      			= chat_in.chat.buf[3] & 0x04 ? 1 : 0;
		chat_out.authorization.at.read_dg4 					= chat_in.chat.buf[3] & 0x08 ? 1 : 0;
		chat_out.authorization.at.read_dg5 					= chat_in.chat.buf[3] & 0x10 ? 1 : 0;
		chat_out.authorization.at.read_dg6 					= chat_in.chat.buf[3] & 0x20 ? 1 : 0;
		chat_out.authorization.at.read_dg7 					= chat_in.chat.buf[3] & 0x40 ? 1 : 0;
		chat_out.authorization.at.read_dg8 					= chat_in.chat.buf[3] & 0x80 ? 1 : 0;
		chat_out.authorization.at.read_dg9        			= chat_in.chat.buf[2] & 0x01 ? 1 : 0;
		chat_out.authorization.at.read_dg10                	= chat_in.chat.buf[2] & 0x02 ? 1 : 0;
		chat_out.authorization.at.read_dg11     			= chat_in.chat.buf[2] & 0x04 ? 1 : 0;
		chat_out.authorization.at.read_dg12					= chat_in.chat.buf[2] & 0x08 ? 1 : 0;
		chat_out.authorization.at.read_dg13					= chat_in.chat.buf[2] & 0x10 ? 1 : 0;
		chat_out.authorization.at.read_dg14					= chat_in.chat.buf[2] & 0x20 ? 1 : 0;
		chat_out.authorization.at.read_dg15					= chat_in.chat.buf[2] & 0x40 ? 1 : 0;
		chat_out.authorization.at.read_dg16					= chat_in.chat.buf[2] & 0x80 ? 1 : 0;
		chat_out.authorization.at.read_dg17        			= chat_in.chat.buf[1] & 0x01 ? 1 : 0;
		chat_out.authorization.at.read_dg18                	= chat_in.chat.buf[1] & 0x02 ? 1 : 0;
		chat_out.authorization.at.read_dg19     			= chat_in.chat.buf[1] & 0x04 ? 1 : 0;
		chat_out.authorization.at.read_dg20					= chat_in.chat.buf[1] & 0x08 ? 1 : 0;
		chat_out.authorization.at.read_dg21					= chat_in.chat.buf[1] & 0x10 ? 1 : 0;
		chat_out.authorization.at.RFU1						= chat_in.chat.buf[1] & 0x20 ? 1 : 0;
		chat_out.authorization.at.RFU2						= chat_in.chat.buf[1] & 0x40 ? 1 : 0;
		chat_out.authorization.at.RFU3						= chat_in.chat.buf[1] & 0x80 ? 1 : 0;
		chat_out.authorization.at.RFU4						= chat_in.chat.buf[0] & 0x01 ? 1 : 0;
		chat_out.authorization.at.write_dg21				= chat_in.chat.buf[0] & 0x02 ? 1 : 0;
		chat_out.authorization.at.write_dg20        		= chat_in.chat.buf[0] & 0x04 ? 1 : 0;
		chat_out.authorization.at.write_dg19               	= chat_in.chat.buf[0] & 0x08 ? 1 : 0;
		chat_out.authorization.at.write_dg18    			= chat_in.chat.buf[0] & 0x10 ? 1 : 0;
		chat_out.authorization.at.write_dg17				= chat_in.chat.buf[0] & 0x20 ? 1 : 0;
		chat_out.authorization.at.role						= chat_in.chat.buf[0] >> 5;
	} else if (chat_in.authTerminalID == st) {
		if (chat_in.chat.size != 1) {
			goto err;
		}
        
		chat_out.type = TT_ST;
		chat_out.authorization.st.generate_signature 			= chat_in.chat.buf[0] & 0x01 ? 1 : 0;
		chat_out.authorization.st.generate_qualified_signature 	= chat_in.chat.buf[0] & 0x02 ? 1 : 0;
		chat_out.authorization.st.RFU1							= chat_in.chat.buf[0] & 0x04 ? 1 : 0;
		chat_out.authorization.st.RFU2							= chat_in.chat.buf[0] & 0x08 ? 1 : 0;
		chat_out.authorization.st.RFU3							= chat_in.chat.buf[0] & 0x10 ? 1 : 0;
		chat_out.authorization.st.RFU4							= chat_in.chat.buf[0] & 0x20 ? 1 : 0;
		chat_out.authorization.st.role							= chat_in.chat.buf[0] >> 5;
	}
    
	r = true;
    
err:
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &is, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &at, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &st, 1);
    
	return r;
}

int fill_vector(const void *buffer, size_t size,
                void *application_specific_key)
{
	int r = -1;
	std::vector<unsigned char> *v = (std::vector<unsigned char> *) application_specific_key;
	const unsigned char *in = (const unsigned char *) buffer;
    
	if (!v || !in) {
		goto err;
	}
    
	while (size) {
		v->push_back(*in);
		in++;
		size--;
	}
    
	r = in - (unsigned char *) buffer;
    
err:
	return r;
}

bool encode_CertificateHolderAuthorizationTemplate_t(const struct chat *chat_in, std::vector<unsigned char> &chat_out)
{
	bool r = false;
	CertificateHolderAuthorizationTemplate_t chat_tmp;
	chat_tmp.authTerminalID.buf = NULL;
	chat_tmp.authTerminalID.size = 0;
	unsigned char buf[5] = {0, 0, 0, 0, 0};
	chat_tmp.chat.buf = buf;
	asn_enc_rval_t er;
    
	if (!chat_in)
		goto err;
    
	chat_out.clear();
    
	switch (chat_in->type) {
		case TT_IS:
			chat_tmp.authTerminalID = makeOID(id_IS);
			chat_tmp.chat.size = 1 * sizeof(unsigned char);
            
			if (chat_in->authorization.is.read_finger 	) chat_tmp.chat.buf[0] |= 0x01;
			if (chat_in->authorization.is.read_iris  	) chat_tmp.chat.buf[0] |= 0x02;
			if (chat_in->authorization.is.RFU1     		) chat_tmp.chat.buf[0] |= 0x04;
			if (chat_in->authorization.is.RFU2			) chat_tmp.chat.buf[0] |= 0x08;
			if (chat_in->authorization.is.RFU3			) chat_tmp.chat.buf[0] |= 0x10;
			if (chat_in->authorization.is.read_eid		) chat_tmp.chat.buf[0] |= 0x20;
			chat_tmp.chat.buf[0]											   |= ((chat_in->authorization.is.role & 0x03) << 5);
			break;
            
		case TT_AT:
			chat_tmp.authTerminalID = makeOID(id_AT);
			chat_tmp.chat.size = 5 * sizeof(unsigned char);
            
			if (chat_in->authorization.at.age_verification 				) chat_tmp.chat.buf[4] |= 0x01;
			if (chat_in->authorization.at.community_id_verification 	) chat_tmp.chat.buf[4] |= 0x02;
			if (chat_in->authorization.at.restricted_id 				) chat_tmp.chat.buf[4] |= 0x04;
			if (chat_in->authorization.at.privileged 					) chat_tmp.chat.buf[4] |= 0x08;
			if (chat_in->authorization.at.can_allowed 					) chat_tmp.chat.buf[4] |= 0x10;
			if (chat_in->authorization.at.pin_management 				) chat_tmp.chat.buf[4] |= 0x20;
			if (chat_in->authorization.at.install_cert 					) chat_tmp.chat.buf[4] |= 0x40;
			if (chat_in->authorization.at.install_qualified_cert 		) chat_tmp.chat.buf[4] |= 0x80;
			if (chat_in->authorization.at.read_dg1         				) chat_tmp.chat.buf[3] |= 0x01;
			if (chat_in->authorization.at.read_dg2                  	) chat_tmp.chat.buf[3] |= 0x02;
			if (chat_in->authorization.at.read_dg3      				) chat_tmp.chat.buf[3] |= 0x04;
			if (chat_in->authorization.at.read_dg4 						) chat_tmp.chat.buf[3] |= 0x08;
			if (chat_in->authorization.at.read_dg5 						) chat_tmp.chat.buf[3] |= 0x10;
			if (chat_in->authorization.at.read_dg6 						) chat_tmp.chat.buf[3] |= 0x20;
			if (chat_in->authorization.at.read_dg7 						) chat_tmp.chat.buf[3] |= 0x40;
			if (chat_in->authorization.at.read_dg8 						) chat_tmp.chat.buf[3] |= 0x80;
			if (chat_in->authorization.at.read_dg9        				) chat_tmp.chat.buf[2] |= 0x01;
			if (chat_in->authorization.at.read_dg10                		) chat_tmp.chat.buf[2] |= 0x02;
			if (chat_in->authorization.at.read_dg11     				) chat_tmp.chat.buf[2] |= 0x04;
			if (chat_in->authorization.at.read_dg12						) chat_tmp.chat.buf[2] |= 0x08;
			if (chat_in->authorization.at.read_dg13						) chat_tmp.chat.buf[2] |= 0x10;
			if (chat_in->authorization.at.read_dg14						) chat_tmp.chat.buf[2] |= 0x20;
			if (chat_in->authorization.at.read_dg15						) chat_tmp.chat.buf[2] |= 0x40;
			if (chat_in->authorization.at.read_dg16						) chat_tmp.chat.buf[2] |= 0x80;
			if (chat_in->authorization.at.read_dg17        				) chat_tmp.chat.buf[1] |= 0x01;
			if (chat_in->authorization.at.read_dg18             		) chat_tmp.chat.buf[1] |= 0x02;
			if (chat_in->authorization.at.read_dg19     				) chat_tmp.chat.buf[1] |= 0x04;
			if (chat_in->authorization.at.read_dg20						) chat_tmp.chat.buf[1] |= 0x08;
			if (chat_in->authorization.at.read_dg21						) chat_tmp.chat.buf[1] |= 0x10;
			if (chat_in->authorization.at.RFU1							) chat_tmp.chat.buf[1] |= 0x20;
			if (chat_in->authorization.at.RFU2							) chat_tmp.chat.buf[1] |= 0x40;
			if (chat_in->authorization.at.RFU3							) chat_tmp.chat.buf[1] |= 0x80;
			if (chat_in->authorization.at.RFU4							) chat_tmp.chat.buf[0] |= 0x01;
			if (chat_in->authorization.at.write_dg21					) chat_tmp.chat.buf[0] |= 0x02;
			if (chat_in->authorization.at.write_dg20        			) chat_tmp.chat.buf[0] |= 0x04;
			if (chat_in->authorization.at.write_dg19                	) chat_tmp.chat.buf[0] |= 0x08;
			if (chat_in->authorization.at.write_dg18    				) chat_tmp.chat.buf[0] |= 0x10;
			if (chat_in->authorization.at.write_dg17					) chat_tmp.chat.buf[0] |= 0x20;
			chat_tmp.chat.buf[0] 											  				   |= ((chat_in->authorization.at.role & 0x03) << 5);
			break;
            
		case TT_ST:
			chat_tmp.authTerminalID = makeOID(id_ST);
			chat_tmp.chat.size = 1 * sizeof(unsigned char);
            
			if (chat_in->authorization.st.generate_signature 			) chat_tmp.chat.buf[0] |= 0x01;
			if (chat_in->authorization.st.generate_qualified_signature 	) chat_tmp.chat.buf[0] |= 0x02;
			if (chat_in->authorization.st.RFU1							) chat_tmp.chat.buf[0] |= 0x04;
			if (chat_in->authorization.st.RFU2							) chat_tmp.chat.buf[0] |= 0x08;
			if (chat_in->authorization.st.RFU3							) chat_tmp.chat.buf[0] |= 0x10;
			if (chat_in->authorization.st.RFU4							) chat_tmp.chat.buf[0] |= 0x20;
			chat_tmp.chat.buf[0]															   |= ((chat_in->authorization.st.role & 0x03) << 5);
			break;
            
		default:
			goto err;
	}
    
	er = der_encode(&asn_DEF_CertificateHolderAuthorizationTemplate, &chat_tmp, fill_vector, &chat_out);
	if (er.encoded == -1) {
		goto err;
	}
    
	r = true;
    
err:
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &chat_tmp.authTerminalID, 1);
    
	return r;
}

NPACLIENT_ERROR nPADataBuffer2Vector(const nPADataBuffer_t DataBuffer, std::vector<unsigned char> &vec)
{
	if( 0x00 == DataBuffer.pDataBuffer )
		return NPACLIENT_ERROR_INVALID_PARAMETER1;

    for(int i = 0; i < DataBuffer.bufferSize; i++)
    {
        vec.push_back((DataBuffer.pDataBuffer)[i]);
    }

	return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR nPAFreeDataBuffer(nPADataBuffer_t* pDataBuffer)
{
	// The given buffer isn't valid.
	if (0x00 == pDataBuffer)
		return NPACLIENT_ERROR_INVALID_PARAMETER1;
    
	// Free the memory and set the members to initial values.
	free(pDataBuffer->pDataBuffer);
	pDataBuffer->pDataBuffer = 0x00;
	pDataBuffer->bufferSize = 0;
	return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR nPAFreeDataBufferList(nPADataBuffer_t** ppDataBufferList, const size_t list_size)
{
	// The given buffer isn't valid.
	if (0x00 == ppDataBufferList)
		return NPACLIENT_ERROR_INVALID_PARAMETER1;

    nPADataBuffer_t* bufTmp = *ppDataBufferList;
    for(unsigned long i = 0; i < list_size; i++)
    {
        nPAFreeDataBuffer(bufTmp);
        bufTmp++;
    }
    free(*ppDataBufferList);
	return NPACLIENT_ERROR_SUCCESS;
}

/*
* TODO: Change returntype to NPACLIENT_ERROR
*/
bool StartConnection(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char* const url, const char* const SessionIdentifier, const char *const PathSecurityParameters)
{
	std::string	strUrl;
    std::string strSessionIdentifier;
    std::string strPSKKey;
	std::string httpsPrefix = "https://";
	std::string httpPrefix = "http://";
    
    if(0x00 == url)
    {
        eCardCore_warn(DEBUG_LEVEL_PAOS, "missing url parameter");
        return false;
    }
    if(0x00 == SessionIdentifier)
    {
        eCardCore_warn(DEBUG_LEVEL_PAOS, "missing SessionIdentifier parameter");
        return false;
    }

    strSessionIdentifier.assign(SessionIdentifier);

	strUrl.assign(url);
	strUrl.append("/?sessionid=");
	strUrl.append(strSessionIdentifier);

	if(strUrl.compare(0, httpsPrefix.length(), httpsPrefix) && strUrl.compare(0, httpPrefix.length(), httpPrefix))
	{
		strUrl.insert(0, httpsPrefix);
	}
    
    if(0x00 != PathSecurityParameters)
    {
        strPSKKey.assign(PathSecurityParameters);
		size_t pos1, pos2;
		pos1 = strPSKKey.find("<PSK>");
		pos1 += 5;
		pos2 = strPSKKey.find("</PSK>");

		//PSK-Tags gefunden
		if (std::string::npos != pos1 && std::string::npos != pos2) {
			strPSKKey = strPSKKey.substr(pos1, pos2 - pos1);
		}
		EID_CLIENT_CONNECTION_ERROR rVal = eIDClientConnectionStartHttp(hConnection, strUrl.c_str(), strSessionIdentifier.c_str(), strPSKKey.c_str(), 0);

		if (rVal != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			eCardCore_warn(DEBUG_LEVEL_PAOS, "eIDClientConnectionStart failed (0x%08X)", rVal);
			return false;
		}
    }
    else
    {
        strPSKKey.assign("");
		EID_CLIENT_CONNECTION_ERROR rVal = eIDClientConnectionStartHttp(hConnection, strUrl.c_str(), NULL, NULL, 0);

		if (rVal != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			eCardCore_warn(DEBUG_LEVEL_PAOS, "eIDClientConnectionStart failed (0x%08X)", rVal);
			return false;
		}
    }
    
	if (*hConnection == 0x00) {
		eCardCore_warn(DEBUG_LEVEL_PAOS, "hConnection == 0x00 (%s:%d)", __FILE__, __LINE__);
		return false;
	}
    
	return true;
}

bool getCertificateInformation( const nPADataBuffer_t certificateDescriptionRaw,
                               enum DescriptionType *certificateDescriptionType,
                               nPADataBuffer_t *certificateDescription,
                               nPADataBuffer_t *serviceName,
                               nPADataBuffer_t *serviceURL)
{
	CertificateDescription_t *certificateDescription_ = 0x00;
    
	if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, certificateDescriptionRaw.pDataBuffer, certificateDescriptionRaw.bufferSize).code != RC_OK)
    {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "getCertificateInformation - Could not parse certificate description.");
		asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
		return false;
	}
    
	PlainTermsOfUsage_t *usage = 0x00;
    
	if (ber_decode(0, &asn_DEF_PlainTermsOfUsage, (void **)&usage,
				   certificateDescription_->termsOfUsage.buf, certificateDescription_->termsOfUsage.size).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "getCertificateInformation - Could not parse certificate description.");
		asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
		return false;
	}
    
	certificateDescription->pDataBuffer = new unsigned char[usage->size];
    
	if (0x00 == certificateDescription->pDataBuffer)
		return false;
    
	/* FIXME add logic to parse the description type */
	*certificateDescriptionType = DT_PLAIN;
	certificateDescription->bufferSize = usage->size;
	memcpy(certificateDescription->pDataBuffer, usage->buf, usage->size);
    
    
 	serviceName->pDataBuffer = new unsigned char[certificateDescription_->subjectName.size];
    
	if (0x00 == serviceName->pDataBuffer)
		return false;
    
	serviceName->bufferSize = certificateDescription_->subjectName.size;
	memcpy(serviceName->pDataBuffer, certificateDescription_->subjectName.buf, serviceName->bufferSize);
    
 	if (0x00 != certificateDescription_->subjectURL)
    {
        serviceURL->pDataBuffer = new unsigned char[certificateDescription_->subjectURL->size];
        
        if (0x00 == serviceURL->pDataBuffer)
            return false;
        
        serviceURL->bufferSize = certificateDescription_->subjectURL->size;
        memcpy(serviceURL->pDataBuffer, certificateDescription_->subjectURL->buf, serviceURL->bufferSize);
    }
    
	asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
	return true;
}

bool getCertificateValidDates( const nPADataBuffer_t certificate, time_t *certificateValidFrom, time_t *certificateValidTo)
{
	CVCertificate_t *CVCertificate = 0x00;
    
	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate, certificate.pDataBuffer, certificate.bufferSize).code != RC_OK)
    {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "getCertificateValidDates - Could not parse terminal certificate.");
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		// @TODO: Do logging ...
		return false;
	}
    
	if (CVCertificate->certBody.certEffectiveDate.buf && CVCertificate->certBody.certEffectiveDate.size)
    {
		std::vector<unsigned char> validFromBuffer(
                                                   CVCertificate->certBody.certEffectiveDate.buf,
                                                   CVCertificate->certBody.certEffectiveDate.buf + CVCertificate->certBody.certEffectiveDate.size);
		*certificateValidFrom = BDRDate::timeFromBCD(validFromBuffer);
	} else {
		eCardCore_warn(DEBUG_LEVEL_CLIENT, "getCertificateValidDates - certificate's effective date missing.");
		certificateValidFrom = 0;
	}
    
	if (CVCertificate->certBody.certExpirationDate.buf && CVCertificate->certBody.certExpirationDate.size) {
		std::vector<unsigned char> validFromBuffer(
                                                   CVCertificate->certBody.certExpirationDate.buf,
                                                   CVCertificate->certBody.certExpirationDate.buf + CVCertificate->certBody.certExpirationDate.size);
		*certificateValidTo = BDRDate::timeFromBCD(validFromBuffer);
	} else {
		eCardCore_warn(DEBUG_LEVEL_CLIENT, "nPAClient::getValidFromDate - certificate's expiration date missing.");
		*certificateValidTo = -1;
	}    
    
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return true;
}

bool getChatInformation(const nPADataBuffer_t requCHAT, const nPADataBuffer_t optCHAT, struct chat *requiredChat, struct chat *optionalChat)
{
	CertificateHolderAuthorizationTemplate_t *chatrequ = NULL;
	CertificateHolderAuthorizationTemplate_t *chatopt = NULL;
	bool r = false;
    
	if (ber_decode(0, &asn_DEF_CertificateHolderAuthorizationTemplate, (void **)&chatrequ,
				   requCHAT.pDataBuffer, requCHAT.bufferSize).code != RC_OK)
    {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "getChatInformation - Could not parse required chat.");
		goto err;
	}
    
	r = decode_CertificateHolderAuthorizationTemplate_t(*chatrequ, *requiredChat);
 
	if( optCHAT.pDataBuffer == 0x00)
    {
		optionalChat->type = TT_invalid;
		/* optionalChat is optional */
		r = true;
	} else {
		if (ber_decode(0, &asn_DEF_CertificateHolderAuthorizationTemplate, (void **)&chatopt,
                       optCHAT.pDataBuffer, optCHAT.bufferSize).code != RC_OK) {
			eCardCore_debug(DEBUG_LEVEL_CLIENT, "getChatInformation - Could not parse optional chat.");
			goto err;
		}
        
		r = decode_CertificateHolderAuthorizationTemplate_t(*chatopt, *optionalChat);
	}
    
err:
	asn_DEF_CertificateHolderAuthorizationTemplate.free_struct(&asn_DEF_CertificateHolderAuthorizationTemplate, chatrequ, 0);
	asn_DEF_CertificateHolderAuthorizationTemplate.free_struct(&asn_DEF_CertificateHolderAuthorizationTemplate, chatopt, 0);
    
	return r;
}

extern "C" NPACLIENT_ERROR __STDCALL__ nPAInitialize(IReaderManager* hReader, ICard** hCard)
{
	try {

        if( 0x00 == hReader )
            return ECARD_PROTOCOL_UNKNOWN;
        
        hReader->addCardDetector(new ePACardDetector());
        
        std::vector<IReader*> readers;

        readers = hReader->getReaders();

        eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %d reader%s", readers.size(), readers.size() == 1 ? "" : "s");
        
        if (readers.empty())
            return NPACLIENT_ERROR_NO_USABLE_READER_PRESENT;
        
        size_t ePACounter = 0;
        
        // Try to find a valid nPA card.
        for (size_t i = 0; i < readers.size(); i++) {
            eCardCore_info(DEBUG_LEVEL_CLIENT, "Trying %s.", readers[i]->getReaderName().c_str());
            
            if (!readers[i]->open())
                continue;
            
            std::vector<unsigned char> atr = readers[i]->getATRForPresentCard();
            hexdump(DEBUG_LEVEL_CLIENT, "Answer-to-Reset (ATR):", DATA(atr), atr.size());
            
            ICard* hTempCard_ = readers[i]->getCard();
            
            if (hTempCard_) {
                // We have more than one card ... So we have to close the old one.
                if (*hCard != 0x00)
                    delete *hCard;
                
                *hCard = hTempCard_;
                ePACounter++;
                eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %s", (*hCard)->getCardDescription().c_str());
                
            } else
                readers[i]->close();
        }
        
        eCardCore_debug(DEBUG_LEVEL_CLIENT, "Found %d nPA%s", ePACounter, ePACounter == 1 ? "" : "s");
        
        // We can only handle one nPA.
        if (1 < ePACounter)
            return NPACLIENT_ERROR_TO_MANY_CARDS_FOUND;
        
        // We need at least one nPA.
        if (1 > ePACounter)
            return NPACLIENT_ERROR_NO_VALID_CARD_FOUND;

        return NPACLIENT_ERROR_SUCCESS;

	} catch (...) {
		return NPACLIENT_ERROR_GENERAL_INITIALIZATION_FAILURE;
	}

	return NPACLIENT_ERROR_SUCCESS;
}

bool validateTransactionData(unsigned char* transaction_data, int transaction_data_length, unsigned char* auxilliary_data, int auxilliary_data_length)
{
	//TODO: use asn1c to determine hash length + offset
	//TODO: support for other Hash algorithms

	SHA224 sha;
	unsigned char result[sha.DIGESTSIZE];

	sha.CalculateDigest(result, transaction_data, transaction_data_length);
	
	hexdump(DEBUG_LEVEL_CRYPTO, "Transaction Data", transaction_data, transaction_data_length);
	hexdump(DEBUG_LEVEL_CRYPTO, "Auxilliary Data", auxilliary_data, auxilliary_data_length);
	hexdump(DEBUG_LEVEL_CRYPTO, "Auxilliary Hash", auxilliary_data+40, auxilliary_data_length-40);
	hexdump(DEBUG_LEVEL_CRYPTO, "Transaction Hash", result, 28);

	if(0x00 != memcmp(auxilliary_data+40,result,sha.DIGESTSIZE)){
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Hash(TransactionData) and Hash from AuxilliaryData do not match");
		return false;
	} else
		return true;
}

extern "C" NPACLIENT_ERROR __STDCALL__ nPAPerformPACE(
	ICard* hCard,
	const nPADataBuffer_t *password,
	const struct chat* chat_selected,
	const struct chat* chat_required,
	const struct chat* chat_optional,
	const nPADataBuffer_t* certificateDescription,
    const nPADataBuffer_t* transactionInfoHidden,
    nPADataBuffer_t* const idPICC,
    nPADataBuffer_t* const CAR,
    nPADataBuffer_t* const caOID,
	struct chat* const chatUsed)
{
	if (0x00 == hCard)
		return NPACLIENT_ERROR_INVALID_PARAMETER1;

    PaceInput pace_input;
    std::vector<unsigned char>  chatSelected, chatOptional, chatRequired;

    if (!chat_selected)
        return NPACLIENT_ERROR_INVALID_PARAMETER2;

    if (!certificateDescription)
        return NPACLIENT_ERROR_INVALID_PARAMETER3;

    if (!chatUsed)
        return NPACLIENT_ERROR_INVALID_PARAMETER4;

    /* FIXME use an other type of secret... */
    pace_input.set_pin_id(PaceInput::pin);
    if (password)
        pace_input.set_pin(std::vector<unsigned char> (password->pDataBuffer,
                    password->pDataBuffer + password->bufferSize));

    pace_input.set_certificate_description(std::vector<unsigned char>
            (certificateDescription->pDataBuffer,
             certificateDescription->pDataBuffer + certificateDescription->bufferSize));

    pace_input.set_transaction_info_hidden(std::vector<unsigned char>
            (transactionInfoHidden->pDataBuffer,
             transactionInfoHidden->pDataBuffer + transactionInfoHidden->bufferSize));

    if (!encode_CertificateHolderAuthorizationTemplate_t(chat_selected, chatSelected))
        return NPACLIENT_ERROR_INVALID_PARAMETER2;
    pace_input.set_chat(chatSelected);

    if (encode_CertificateHolderAuthorizationTemplate_t(chat_optional, chatOptional))
        pace_input.set_chat_optional(chatOptional);

    if (encode_CertificateHolderAuthorizationTemplate_t(chat_required, chatRequired))
        pace_input.set_chat_required(chatRequired);

    // Try to get ePA card
    ePACard &ePA_ = dynamic_cast<ePACard &>(*hCard);

    std::vector<unsigned char> vecIdPICC;
    std::vector<unsigned char> vecCAR;
    std::vector<unsigned char> vecCaOID;
    std::vector<unsigned char> vecChatUsed;

    // Run the PACE protocol.
    ECARD_STATUS status_ = ePAPerformPACE(ePA_, pace_input, vecCAR, vecIdPICC, vecCaOID, vecChatUsed);
	if(ECARD_SUCCESS != status_)
		return status_;

    CAR->bufferSize = vecCAR.size();
    CAR->pDataBuffer = (unsigned char*) malloc(CAR->bufferSize);
    memcpy(CAR->pDataBuffer, DATA(vecCAR) , vecCAR.size() );

    idPICC->bufferSize = vecIdPICC.size();
    idPICC->pDataBuffer = (unsigned char*) malloc(idPICC->bufferSize);
    memcpy(idPICC->pDataBuffer, DATA(vecIdPICC) , vecIdPICC.size() );

    caOID->bufferSize = vecCaOID.size();
    caOID->pDataBuffer = (unsigned char*) malloc(caOID->bufferSize);
    memcpy(caOID->pDataBuffer, DATA(vecCaOID) , vecCaOID.size() );

	CertificateHolderAuthorizationTemplate_t *chatUsedASN = NULL;
	if (ber_decode(0, &asn_DEF_CertificateHolderAuthorizationTemplate, (void **)&chatUsedASN,
				   DATA(vecChatUsed), vecChatUsed.size()).code != RC_OK)
    {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "Could not parse used chat.");
        return NPACLIENT_ERROR_NO_USABLE_READER_PRESENT;
	}
    /* FIXME error checking */
    decode_CertificateHolderAuthorizationTemplate_t(
            dynamic_cast<CertificateHolderAuthorizationTemplate_t &>(*chatUsedASN),
            dynamic_cast<struct chat &>(*chatUsed));
    asn_DEF_CertificateHolderAuthorizationTemplate.free_struct(&asn_DEF_CertificateHolderAuthorizationTemplate, chatUsedASN, 0);

    return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR __STDCALL__ nPAeIdgetEfCardAccess(
    ICard* hCard,
    nPADataBuffer_t* const efCardAccess)
{
	try {

        // Try to get ePA card
        ePACard &ePA_ = dynamic_cast<ePACard &>(*hCard);

        std::vector<unsigned char> vecEFCardAccess = ePA_.get_ef_cardaccess();

        efCardAccess->bufferSize = vecEFCardAccess.size();
        efCardAccess->pDataBuffer = (unsigned char*) malloc(efCardAccess->bufferSize);
        memcpy(efCardAccess->pDataBuffer, DATA(vecEFCardAccess) , vecEFCardAccess.size() );

    } catch (...) {
        return NPACLIENT_ERROR_GENERAL_INITIALIZATION_FAILURE;
    }
    
    return ECARD_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAPerformTerminalAuthentication(
	ICard* hCard,
    EIDCLIENT_CONNECTION_HANDLE hConnection,
    const nPADataBuffer_t transactionInfo,
    const nPADataBuffer_t transactionInfoHidden,
    const nPADataBuffer_t efCardAccess,
    const nPADataBuffer_t selectedCHAT,
    const nPADataBuffer_t idPICC,
    const nPADataBuffer_t CAR,
    const nPADataBuffer_t authAuxData,
    const nPADataBuffer_t certTerminal,
    const nPADataBuffer_t caOID,
    nPADataBuffer_t* Puk_IFD_DH_CA)
{
	NPACLIENT_ERROR error;
    /* TODO check authenticatedAuxiliaryData_ with transactionInfo and transactionInfoHidden */

	if (0x00 == hCard)
		return ECARD_ERROR;

	try {
        // Try to get ePA card
        ePACard &ePA_ = dynamic_cast<ePACard &>(*hCard);
        
        std::vector<std::vector<unsigned char> > list_certificates;
        std::vector<unsigned char> terminalCertificate_;
        std::vector<unsigned char> authenticatedAuxiliaryData_;
       
//        nPADataBuffer_t Puk_IFD_DH_CA = {0x00, 0};
        nPADataBuffer_t* pBufCertList = NULL;
        unsigned long list_size = 0;

		EID_ECARD_CLIENT_PAOS_ERROR err = getTerminalAuthenticationData(hConnection, efCardAccess, selectedCHAT, CAR, idPICC, &pBufCertList, &list_size, Puk_IFD_DH_CA);
		if(err != EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS)
			return err;

        nPADataBuffer_t* bufTmp = pBufCertList;
        for(unsigned long i = 0; i < list_size; i++)
        {
            std::vector<unsigned char> vecCert;
            
            nPADataBuffer2Vector(*bufTmp, vecCert);
            list_certificates.push_back(vecCert);
            bufTmp++;
        }
        
        nPAFreeDataBufferList(&pBufCertList, list_size);
        
        std::vector<unsigned char> Puk_IFD_DH_;
        
		nPADataBuffer2Vector(*Puk_IFD_DH_CA, Puk_IFD_DH_);
        nPADataBuffer2Vector(authAuxData, authenticatedAuxiliaryData_);
        nPADataBuffer2Vector(certTerminal, terminalCertificate_);
        
        // Only used in CA
        std::vector<unsigned char> toBeSigned;
  
        std::vector<unsigned char> carCVCA_;
        carCVCA_.assign(CAR.pDataBuffer, CAR.pDataBuffer + CAR.bufferSize);

        std::vector<unsigned char> caOID_;
        caOID_.assign(caOID.pDataBuffer, caOID.pDataBuffer + caOID.bufferSize);

        // Run the TA protocol.
        error = ePAPerformTA(ePA_, carCVCA_, list_certificates, terminalCertificate_,
                             caOID_, Puk_IFD_DH_, authenticatedAuxiliaryData_, toBeSigned);
        if( ECARD_SUCCESS == error )
        {
          nPADataBuffer_t challenge = {0x00, 0};
          nPADataBuffer_t signature = {0x00, 0};
        
          challenge.bufferSize = toBeSigned.size();
          challenge.pDataBuffer = (unsigned char*) malloc(challenge.bufferSize);
          memcpy(challenge.pDataBuffer, DATA(toBeSigned) , toBeSigned.size() );
        
          createSignature(hConnection, challenge, &signature);
        
          std::vector<unsigned char> sendSignature_;
        
          nPADataBuffer2Vector(signature, sendSignature_);

          error = ePASendSignature(*hCard, sendSignature_);

          nPAFreeDataBuffer(&challenge);
          nPAFreeDataBuffer(&signature);
        }
        
	} catch (...)
    {
		return NPACLIENT_ERROR_TA_FAILED;
	}

	return error;
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAPerformChipAuthentication(
	ICard* hCard, EIDCLIENT_CONNECTION_HANDLE hConnection, const nPADataBuffer_t caOID, const nPADataBuffer_t Puk_IFD_DH_CA, nPADataBuffer_t* GeneralAuthenticationResult, nPADataBuffer_t* efCardSecurity)
{
	if (0x00 == hCard)
        return ECARD_ERROR;

    try {

        // Try to get ePA card
        ePACard &ePA_ = dynamic_cast<ePACard &>(*hCard);

        const std::vector<unsigned char> ef_cardsecurity = ePA_.get_ef_cardsecurity();

        efCardSecurity->bufferSize = ef_cardsecurity.size();
        efCardSecurity->pDataBuffer = (unsigned char*) malloc(efCardSecurity->bufferSize);
        memcpy(efCardSecurity->pDataBuffer, DATA(ef_cardsecurity) , ef_cardsecurity.size() );

        std::vector<unsigned char> caOID_;
        caOID_.assign(caOID.pDataBuffer, caOID.pDataBuffer + caOID.bufferSize);

        std::vector<unsigned char> Puk_IFD_DH_;
        nPADataBuffer2Vector(Puk_IFD_DH_CA, Puk_IFD_DH_);

        std::vector<unsigned char> GeneralAuthenticationResult_;

		ECARD_STATUS err = ePAPerformCA(*hCard, caOID_, Puk_IFD_DH_, GeneralAuthenticationResult_);
		if(ECARD_SUCCESS != err)
        {
            return err;
        }

        GeneralAuthenticationResult->bufferSize = GeneralAuthenticationResult_.size();
        GeneralAuthenticationResult->pDataBuffer = (unsigned char*) malloc(GeneralAuthenticationResult->bufferSize);
        memcpy(GeneralAuthenticationResult->pDataBuffer, DATA(GeneralAuthenticationResult_) , GeneralAuthenticationResult_.size() );

        return NPACLIENT_ERROR_SUCCESS;

	} catch (...) {
		return NPACLIENT_ERROR_CA_FAILED;
	}
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAReadAttributes(
	ICard* hCard, EIDCLIENT_CONNECTION_HANDLE hConnection, nPADataBuffer_t GeneralAuthenticationResult, nPADataBuffer_t efCardSecurity)
{
    std::vector<RAPDU>      rapdus;
    std::vector<CAPDU>      capdus;

	try {

        std::vector<unsigned char> GAResult;        
        std::vector<unsigned char> AuthToken;
        std::vector<unsigned char> Nonce;
  
        nPADataBuffer2Vector(GeneralAuthenticationResult, GAResult);
        
        // größe von GAResult prüfen
        for(int m = 0; m < 8; m++)
        {
            AuthToken.push_back(GAResult.at(14 + m));
        }
        for(int n = 0; n < 8; n++)
        {
            Nonce.push_back(GAResult.at(4 + n));
        }
        
        nPADataBuffer_t bufAuthToken = {0x00, 0};
        
        bufAuthToken.bufferSize = AuthToken.size();
        bufAuthToken.pDataBuffer = (unsigned char*) malloc(bufAuthToken.bufferSize);
        memcpy(bufAuthToken.pDataBuffer, DATA(AuthToken) , AuthToken.size() );
        
        nPADataBuffer_t bufNonce = {0x00, 0};
        
        bufNonce.bufferSize = Nonce.size();
        bufNonce.pDataBuffer = (unsigned char*) malloc(bufNonce.bufferSize);
        memcpy(bufNonce.pDataBuffer, DATA(Nonce), Nonce.size() );
        
        nPADataBuffer_t* pBufApduList = NULL;
        unsigned long list_size = 0;
        
        EID_ECARD_CLIENT_PAOS_ERROR rVal = EAC2OutputCardSecurity(hConnection, efCardSecurity, bufAuthToken, bufNonce, &pBufApduList, &list_size);
		if(rVal != EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS)
			return NPACLIENT_ERROR_READ_FAILED;

        //        nPAFreeDataBuffer(&efCardSecurity);
        nPAFreeDataBuffer(&bufAuthToken);
        nPAFreeDataBuffer(&bufNonce);
        
        while (list_size > 0) {
            capdus.clear();
            rapdus.clear();

            nPADataBuffer_t* bufTmp = pBufApduList;
            for(unsigned long i = 0; i < list_size; i++)
            {
                std::vector<unsigned char> vecAPDU;

                nPADataBuffer2Vector(*bufTmp, vecAPDU);
                capdus.push_back(vecAPDU);

                bufTmp++;
            }

            nPAFreeDataBufferList(&pBufApduList, list_size);


            rapdus = hCard->transceive(capdus);

            unsigned long list_inApdus_size = rapdus.size();
            nPADataBuffer_t* list_inApdus = (nPADataBuffer_t*) malloc(list_inApdus_size * sizeof(nPADataBuffer_t));

            bufTmp = list_inApdus;

            std::vector<unsigned char> rapdu;
            for (size_t i = 0; i < rapdus.size(); ++i)
            {
                rapdu = rapdus.at(i).asBuffer();
                bufTmp->bufferSize = rapdu.size();
                bufTmp->pDataBuffer = (unsigned char*) malloc(bufTmp->bufferSize);
                memcpy(bufTmp->pDataBuffer, DATA(rapdu) , rapdu.size() );
                bufTmp++;
            }
        
            pBufApduList = NULL;
            list_size = 0;

            rVal = readAttributes(hConnection, list_inApdus, list_inApdus_size, &pBufApduList, &list_size);
            if(rVal != EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS)
                return NPACLIENT_ERROR_READ_FAILED;

            nPAFreeDataBufferList(&list_inApdus, list_inApdus_size);
        }
        
	} catch (...) {
		return NPACLIENT_ERROR_READ_FAILED;
	}

	return ECARD_SUCCESS;
}

extern "C" NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocolWithParamMap(
	AuthenticationParams_t paraMap,
	ECARD_PROTOCOL usedProtocol,
	const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
	const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
	if (!fnUserInteractionCallback)
		return NPACLIENT_ERROR_INVALID_PARAMETER3;

	if (!fnCurrentStateCallback)
		return NPACLIENT_ERROR_INVALID_PARAMETER4;

    IReaderManager*     hReader = 0x00;
    
    // Connect to the underlying smart card system.
    switch (usedProtocol) {
        case PROTOCOL_PCSC:
#ifndef DISABLE_PCSC
			hReader = new PCSCManager(paraMap.m_userSelectedCardReader);
#endif
            break;
        case PROTOCOL_EXTERNAL:
#ifndef DISABLE_EXTERNAL
            hReader = new ExternalManager();
#endif
            break;
        default:
            return ECARD_PROTOCOL_UNKNOWN;
    }
    if( 0x00 == hReader )
        return ECARD_PROTOCOL_UNKNOWN;
    
	struct chat chat_invalid;
	chat_invalid.type = TT_invalid;
	unsigned char p[MAX_PIN_SIZE];
	char pin_required = 0;
	/* FIXME get the right type of secret (PI_PIN may not be correct) */
	enum PinID pin_id = PI_PIN;

	NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

	nPADataBuffer_t certificate = {0x00, 0};
	nPADataBuffer_t certificateDescription = {0x00, 0};
	nPADataBuffer_t certificateDescriptionRaw = {0x00, 0};
	nPADataBuffer_t serviceName = {0x00, 0};
	nPADataBuffer_t serviceURL = {0x00, 0};
	nPADataBuffer_t requiredCHAT = {0x00, 0};
	nPADataBuffer_t optionalCHAT = {0x00, 0};
	nPADataBuffer_t authenticatedAuxiliaryData = {0x00, 0};
	nPADataBuffer_t selectedCHAT = {0x00, 0};
	nPADataBuffer_t efCardAccess = {0x00, 0};
	nPADataBuffer_t idPICC = {0x00, 0};
	nPADataBuffer_t CAR = {0x00, 0};
    nPADataBuffer_t caOID = {0x00, 0};
    nPADataBuffer_t Puk_IFD_DH_CA = {0x00, 0};
    nPADataBuffer_t GeneralAuthenticationResult = {0x00, 0};
    nPADataBuffer_t efCardSecurity = {0x00, 0};
    nPADataBuffer_t transactionInfo = {0x00, 0};
    nPADataBuffer_t transactionInfoHidden = {0x00, 0};
    std::string  strTransactionInfoHidden = "";

	struct chat chatRequired;
	struct chat chatOptional;

    std::vector<unsigned char>   vecChatSelected;

	time_t certificateValidFrom = 0;
	time_t certificateValidTo = 0;
	enum DescriptionType description_type = DT_UNDEF;

    EIDCLIENT_CONNECTION_HANDLE hConnection = 0x00;

    ICard* hCard = 0x00;
    
    std::string  strURL("");
    std::string  strSessionIdentifier("");
    std::string  strPSKKey("");

    /* get transactionInfoHidden */
	if( paraMap.m_transactionURL && strlen(paraMap.m_transactionURL) > 0 ) {
        EID_CLIENT_CONNECTION_ERROR err;
        strURL.assign(paraMap.m_transactionURL);

		err = eIDClientConnectionStartHttp(&hConnection, strURL.c_str(), NULL, NULL, 0);
        if(err != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
        {
            // remove card first !!
            if( 0x00 != hCard)
                delete hCard;
            if( 0x00 != hReader)
                delete hReader;
            return err;
        }


        char buf[10000];
        memset(buf, 0x00, sizeof buf);
        size_t buf_len = sizeof buf;

        err = eIDClientConnectionTransceive(hConnection, NULL, 0, buf, &buf_len);
        if(err != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
        {
            eCardCore_warn(DEBUG_LEVEL_PAOS, "Error while transmit: %x", err);
			eIDClientConnectionEnd(hConnection);
			return err;
		}
        strTransactionInfoHidden.assign(buf, buf_len);
        transactionInfoHidden.pDataBuffer = (unsigned char *) strTransactionInfoHidden.c_str();
        transactionInfoHidden.bufferSize = strTransactionInfoHidden.length();

        err = eIDClientConnectionEnd(hConnection);
        if(err != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
        {
            eCardCore_warn(DEBUG_LEVEL_PAOS, "Error while ending Connection: %x", err);
			return err;
        }
        hConnection = 0x00;
        /* have transactionInfoHidden */
    }
    
    if( paraMap.m_serverAddress )
        strURL.assign(paraMap.m_serverAddress);
    if( paraMap.m_sessionIdentifier )
        strSessionIdentifier.assign(paraMap.m_sessionIdentifier);
    if( paraMap.m_pathSecurityParameters)
        strPSKKey.assign(paraMap.m_pathSecurityParameters);

    error = nPAInitialize(hReader, &hCard);
 	fnCurrentStateCallback(NPACLIENT_STATE_INITIALIZE, error);

    if (error != NPACLIENT_ERROR_SUCCESS)
    {
        if( 0x00 != hReader)
            delete hReader;
        return error;
    }

    if( false == StartConnection(&hConnection, strURL.c_str(), strSessionIdentifier.c_str(), strPSKKey.c_str()) )
    {
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return NPACLIENT_ERROR_CLIENT_CONNECTION_ERROR;
    }
  
	EID_ECARD_CLIENT_PAOS_ERROR paoserr = startPAOS(hConnection, strSessionIdentifier.c_str());
    if( EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS != paoserr )
    {
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return paoserr;
    }
    
    if(CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT == 1){
		return NPACLIENT_ERROR_SUCCESS;
	}

	paoserr = getEACSessionInfo(hConnection, strSessionIdentifier.c_str(),
		&requiredCHAT, &optionalCHAT,
		&authenticatedAuxiliaryData, &certificate,
		&certificateDescriptionRaw, &transactionInfo);
    if( EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS != paoserr )
    {
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return paoserr;
    }
    
	if(0x00 != transactionInfoHidden.pDataBuffer){
		if(!validateTransactionData(transactionInfoHidden.pDataBuffer,transactionInfoHidden.bufferSize,authenticatedAuxiliaryData.pDataBuffer,authenticatedAuxiliaryData.bufferSize))
			return NPACLIENT_ERROR_TRANSACTION_HASH_NOT_VALID;
	}
	   

	fnCurrentStateCallback(NPACLIENT_STATE_GOT_PACE_INFO, error);

	getCertificateInformation(certificateDescriptionRaw, &description_type, &certificateDescription, &serviceName, &serviceURL);
    getCertificateValidDates(certificate, &certificateValidFrom, &certificateValidTo);
    getChatInformation(requiredCHAT, optionalCHAT, &chatRequired, &chatOptional);

	SPDescription_t descriptionNew = {
		description_type,
		certificateDescription,
		serviceName,
		serviceURL,
		chatRequired,
		chatOptional,
		certificateValidFrom,
		certificateValidTo,
        transactionInfo,
        transactionInfoHidden,
	};
  
    if(!hCard->getSubSystem()->supportsPACE())
        pin_required = 1;
    else
        pin_required = 0;

	UserInput_t inputNew = {
	   	pin_required,
	   	pin_id,
	   	chatRequired,
	   	{p, 0}
   	};
    
	error = fnUserInteractionCallback(&descriptionNew, &inputNew);
	if (error != NPACLIENT_ERROR_SUCCESS) {
		// end ClientConnection before return
		eIDClientConnectionEnd(hConnection);
        hConnection = 0x00;
        // clean up allocated memory before return
        nPAFreeDataBuffer(&certificate);
        nPAFreeDataBuffer(&authenticatedAuxiliaryData);
        nPAFreeDataBuffer(&selectedCHAT);
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return error;
	}
 
    error = nPAPerformPACE(hCard, &inputNew.pin, &inputNew.chat_selected, &chatRequired, &chatOptional,
            &certificateDescriptionRaw, &transactionInfoHidden, &idPICC, &CAR,
            &caOID, &inputNew.chat_selected);

    nPAFreeDataBuffer(&certificateDescription);
    nPAFreeDataBuffer(&certificateDescriptionRaw);
    nPAFreeDataBuffer(&serviceName);
    nPAFreeDataBuffer(&serviceURL);
    nPAFreeDataBuffer(&requiredCHAT);
    nPAFreeDataBuffer(&optionalCHAT);
    
    fnCurrentStateCallback(NPACLIENT_STATE_PACE_PERFORMED, error);
 
	if (error != NPACLIENT_ERROR_SUCCESS)
    {
		// end ClientConnection before return
		eIDClientConnectionEnd(hConnection);
        hConnection = 0x00;
        // clean up allocated memory before return
        nPAFreeDataBuffer(&certificate);
        nPAFreeDataBuffer(&authenticatedAuxiliaryData);
        nPAFreeDataBuffer(&selectedCHAT);
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return error;
    }
    
    encode_CertificateHolderAuthorizationTemplate_t(&inputNew.chat_selected, vecChatSelected);
    
    selectedCHAT.bufferSize = vecChatSelected.size();
    selectedCHAT.pDataBuffer = (unsigned char*) malloc(selectedCHAT.bufferSize);
    memcpy(selectedCHAT.pDataBuffer, DATA(vecChatSelected), vecChatSelected.size() );

    nPAeIdgetEfCardAccess(hCard, &efCardAccess);

	error = nPAPerformTerminalAuthentication(hCard, hConnection, transactionInfo, transactionInfoHidden, efCardAccess, selectedCHAT, idPICC, CAR, authenticatedAuxiliaryData, certificate, caOID, &Puk_IFD_DH_CA);
    fnCurrentStateCallback(NPACLIENT_STATE_TA_PERFORMED, error);
	
    nPAFreeDataBuffer(&efCardAccess);
    nPAFreeDataBuffer(&certificate);
    nPAFreeDataBuffer(&authenticatedAuxiliaryData);
    nPAFreeDataBuffer(&selectedCHAT);
    nPAFreeDataBuffer(&idPICC);
    nPAFreeDataBuffer(&CAR);
    
	if (error != NPACLIENT_ERROR_SUCCESS)
    {
		// end ClientConnection before return
		eIDClientConnectionEnd(hConnection);
        hConnection = 0x00;
        // clean up allocated memory before return
        nPAFreeDataBuffer(&caOID);
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return error;
    }

    error = nPAPerformChipAuthentication(hCard, hConnection, caOID, Puk_IFD_DH_CA, &GeneralAuthenticationResult, &efCardSecurity);
	fnCurrentStateCallback(NPACLIENT_STATE_CA_PERFORMED, error);

    nPAFreeDataBuffer(&caOID);

	if (error != NPACLIENT_ERROR_SUCCESS)
    {
		// end ClientConnection before return
		eIDClientConnectionEnd(hConnection);
        hConnection = 0x00;
        // clean up allocated memory before return
        // remove card first !!
        if( 0x00 != hCard)
            delete hCard;
        if( 0x00 != hReader)
            delete hReader;
        return error;
    }

	error = nPAReadAttributes(hCard, hConnection, GeneralAuthenticationResult, efCardSecurity);
	fnCurrentStateCallback(NPACLIENT_STATE_READ_ATTRIBUTES, error);
 
	eIDClientConnectionEnd(hConnection);
    hConnection = 0x00;

    // remove card first !!
    if( 0x00 != hCard)
        delete hCard;
    if( 0x00 != hReader)
        delete hReader;
    
	return error;
}

extern "C" NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocol(
	const ECARD_READER reader,
	const char *const IdpAddress,
	const char *const SessionIdentifier,
	const char *const PathSecurityParameters,
	const char *const CardReaderName,
	const char *const TransactionURL,
	const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
	const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
	AuthenticationParams_t authParams_;
	authParams_.m_serverAddress				= IdpAddress;
	authParams_.m_sessionIdentifier			= SessionIdentifier;
	authParams_.m_pathSecurityParameters	= PathSecurityParameters;
	authParams_.m_userSelectedCardReader		= CardReaderName;
	authParams_.m_transactionURL = TransactionURL;

	switch(reader)
	{
		case READER_PCSC:
			return nPAeIdPerformAuthenticationProtocolWithParamMap(authParams_, PROTOCOL_PCSC, fnUserInteractionCallback, fnCurrentStateCallback);
		case READER_EXTERNAL:
			return nPAeIdPerformAuthenticationProtocolWithParamMap(authParams_, PROTOCOL_EXTERNAL, fnUserInteractionCallback, fnCurrentStateCallback);
	}
	return NPACLIENT_ERROR_UNKNOWN_READER_TYPE;
}
