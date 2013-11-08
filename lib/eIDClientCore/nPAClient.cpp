/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPAClient.h"

#include "eIDUtils.h"
using namespace Bundesdruckerei::eIDUtils;

#include <CertificateBody.h>
#include <CVCertificate.h>
#include <CertificateDescription.h>
#include <PlainTermsOfUsage.h>
#include <eIDOID.h>
#include <eIDHelper.h>

#include "eCardCore/eCardStatus.h"
#include "nPA-EAC/nPACard.h"

#include <debug.h>
#ifndef DISABLE_PCSC
#include "eCardCore/PCSCManager.h"
#endif
#ifndef DISABLE_EXTERNAL
#include "eCardCore/ExternalManager.h"
#endif

nPAClient *nPAClient::m_instance = 0x00;

extern "C" unsigned char *nPAClient_allocator(
	size_t size)
{
	return new unsigned char[size];
}

/**
 */
extern "C" void nPAClient_deallocator(
	unsigned char *data)
{
	delete [] data;
}

/*
 *
 */
nPAClient *nPAClient::createInstance(
	IIdP *pIdP)
{
	if (0x00 == m_instance)
		m_instance = new nPAClient(pIdP);

	return m_instance;
}

/*
 *
 */
nPAClient::nPAClient(
	IIdP *pIdP) : m_Idp(pIdP), m_hSystem(0x00), m_hCard(0x00), m_clientProtocol(0x00),
	m_protocolState(Unauthenticated)
{
}

/*
 *
 */
nPAClient::~nPAClient(
	void)
{
	// Delete the IdP connection.
	if (0x00 != m_Idp) {
		delete m_Idp;
		m_Idp = 0x00;
	}

	// Delete the protocol stack.
	if (0x00 != m_clientProtocol) {
		delete m_clientProtocol;
		m_clientProtocol = 0x00;
	}

	// Close the card.
	if (0x00 != m_hCard) {
		delete m_hCard;
		m_hCard = 0x00;
	}

	// Close the card subsystem.
	if (0x00 != m_hSystem) {
		delete m_hSystem;
		m_hSystem = 0x00;
	}

	m_instance = 0x00;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::initialize(
	const CharMap *paraMap,
	ECARD_PROTOCOL usedProtocol)
{
	NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

	// Check that we have an valid IdP instance. If not return an error.
	if (0x00 == m_Idp)
		return NPACLIENT_ERROR_IDP_INVALID_CONNECTION;

	// Initialize the IdP connection.
	if ((error = m_Idp->initialize(this)) != NPACLIENT_ERROR_SUCCESS)
		return error;

	// Connect to the underlying smart card system.
	switch (usedProtocol) {
		case PROTOCOL_PCSC: {
#ifdef DISABLE_PCSC
				return ECARD_PROTOCOL_UNKNOWN;
#else
				m_hSystem = new PCSCManager();
#endif
			}
			break;
		case PROTOCOL_EXTERNAL: {
#ifdef DISABLE_EXTERNAL
				return ECARD_PROTOCOL_UNKNOWN;
#else
				m_hSystem = new ExternalManager();
#endif
			}
			break;
		default: {
				return ECARD_PROTOCOL_UNKNOWN;
			}
	}

	// Add an instance of an detection object to the smart card system.
	m_hSystem->addCardDetector(new ePACardDetector());
	vector<IReader *> readers;

	// Is there a specified CardReader?
	if (paraMap->find((char *) "CardReaderName") == paraMap->end())
		readers = m_hSystem->getReaders();

	else {
		IReader *reader = m_hSystem->getReader(*paraMap->find((char *) "CardReaderName")->second);

		if (reader == 0x00)
			return ECARD_NO_SUCH_READER;

		readers.push_back(reader);
	}

	eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %d reader%s", readers.size(), readers.size() == 1 ? "" : "s");

	if (readers.empty())
		return NPACLIENT_ERROR_NO_USABLE_READER_PRESENT;

	size_t ePACounter = 0;

	// Try to find a valid nPA card.
	for (size_t i = 0; i < readers.size(); i++) {
		eCardCore_info(DEBUG_LEVEL_CLIENT, "Trying %s.", readers[i]->getReaderName().c_str());

		if (!readers[i]->open())
			continue;

		ICard *hTempCard_ = readers[i]->getCard();

		if (hTempCard_) {
			// We have more than one card ... So we have to close the old one.
			if (m_hCard != 0x00)
				delete m_hCard;

			m_hCard = hTempCard_;
			ePACounter++;
			eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %s", m_hCard->getCardDescription().c_str());
			vector<unsigned char> atr = readers[i]->getATRForPresentCard();
			hexdump(DEBUG_LEVEL_CLIENT, "Answer-to-Reset (ATR):", DATA(atr),
					atr.size());

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

	// Create the new protocol.
	m_clientProtocol = new ePAClientProtocol(m_hCard);

	if (0x00 == m_clientProtocol)
		return NPACLIENT_ERROR_PROTCOL_INITIALIZATION_FAILD;

	return NPACLIENT_ERROR_SUCCESS;
}

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
	vector<unsigned char> *v = (vector<unsigned char> *) application_specific_key;
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
bool encode_CertificateHolderAuthorizationTemplate_t(const struct chat *chat_in, vector<unsigned char> &chat_out)
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

bool nPAClient::getCHAT(
	struct chat &chatFromCertificate)
{
	CVCertificate_t *CVCertificate = 0x00;
	bool r = false;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   m_Idp->getTerminalCertificate().data(), m_Idp->getTerminalCertificate().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCHAT - Could not parse terminal certificate.");
		goto err;
	}

	r = decode_CertificateHolderAuthorizationTemplate_t(CVCertificate->certBody.certHolderAuthTemplate, chatFromCertificate);

err:
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);

	return r;
}

bool nPAClient::getRequiredCHAT(
	struct chat &requiredChat)
{
	CertificateHolderAuthorizationTemplate_t *chat = NULL;
	bool r = false;

	if (ber_decode(0, &asn_DEF_CertificateHolderAuthorizationTemplate, (void **)&chat,
				   m_Idp->getRequiredChat().data(), m_Idp->getRequiredChat().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getRequiredCHAT - Could not parse required chat.");
		goto err;
	}

	r = decode_CertificateHolderAuthorizationTemplate_t(*chat, requiredChat);

err:
	asn_DEF_CertificateHolderAuthorizationTemplate.free_struct(&asn_DEF_CertificateHolderAuthorizationTemplate, chat, 0);

	return r;
}

bool nPAClient::getOptionalCHAT(
	struct chat &optionalChat)
{
	CertificateHolderAuthorizationTemplate_t *chat = NULL;
	bool r = false;

	if (m_Idp->getOptionalChat().empty()) {
		optionalChat.type = TT_invalid;
		/* optionalChat is optional */
		r = true;
	} else {
		if (ber_decode(0, &asn_DEF_CertificateHolderAuthorizationTemplate, (void **)&chat,
					m_Idp->getOptionalChat().data(), m_Idp->getOptionalChat().size()).code != RC_OK) {
			eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getOptionalChat - Could not parse optional chat.");
			goto err;
		}

		r = decode_CertificateHolderAuthorizationTemplate_t(*chat, optionalChat);
	}

err:
	asn_DEF_CertificateHolderAuthorizationTemplate.free_struct(&asn_DEF_CertificateHolderAuthorizationTemplate, chat, 0);

	return r;
}

/*
 *
 */
bool nPAClient::getValidFromDate(
	time_t &certificateValidFrom)
{
	CVCertificate_t *CVCertificate = 0x00;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   m_Idp->getTerminalCertificate().data(), m_Idp->getTerminalCertificate().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getValidFromDate - Could not parse terminal certificate.");
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		// @TODO: Do logging ...
		return false;
	}

	if (CVCertificate->certBody.certEffectiveDate.buf && CVCertificate->certBody.certEffectiveDate.size) {
		std::vector<unsigned char> validFromBuffer(
			CVCertificate->certBody.certEffectiveDate.buf,
			CVCertificate->certBody.certEffectiveDate.buf + CVCertificate->certBody.certEffectiveDate.size);
		certificateValidFrom = BDRDate::timeFromBCD(validFromBuffer);
	} else {
		eCardCore_warn(DEBUG_LEVEL_CLIENT, "nPAClient::getValidFromDate - certificate's effective date missing.");
		certificateValidFrom = 0;
	}
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return true;
}

bool nPAClient::getValidToDate(
	time_t &certificateValidTo)
{
	CVCertificate_t *CVCertificate = 0x00;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   m_Idp->getTerminalCertificate().data(), m_Idp->getTerminalCertificate().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getValidToDate - Could not parse terminal certificate.");
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return false;
	}

	if (CVCertificate->certBody.certExpirationDate.buf && CVCertificate->certBody.certExpirationDate.size) {
		std::vector<unsigned char> validFromBuffer(
			CVCertificate->certBody.certExpirationDate.buf,
			CVCertificate->certBody.certExpirationDate.buf + CVCertificate->certBody.certExpirationDate.size);
		certificateValidTo = BDRDate::timeFromBCD(validFromBuffer);
	} else {
		eCardCore_warn(DEBUG_LEVEL_CLIENT, "nPAClient::getValidFromDate - certificate's expiration date missing.");
		certificateValidTo = -1;
	}
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return true;
}

bool nPAClient::getCertificateDescription(
	enum DescriptionType &certificateDescriptionType,
	nPADataBuffer_t &certificateDescription)
{
	CertificateDescription_t *certificateDescription_ = 0x00;

	if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_,
				   m_Idp->getCertificateDescription().data(), m_Idp->getCertificateDescription().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCertificateDescription - Could not parse certificate description.");
		asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
		return false;
	}

	PlainTermsOfUsage_t *usage = 0x00;

	if (ber_decode(0, &asn_DEF_PlainTermsOfUsage, (void **)&usage,
				   certificateDescription_->termsOfUsage.buf, certificateDescription_->termsOfUsage.size).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCertificateDescription - Could not parse certificate description.");
		asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
		return false;
	}

	certificateDescription.pDataBuffer = new unsigned char[usage->size];

	if (0x00 == certificateDescription.pDataBuffer)
		return false;

	/* FIXME add logic to parse the description type */
	certificateDescriptionType = DT_PLAIN;
	certificateDescription.bufferSize = usage->size;
	memcpy(certificateDescription.pDataBuffer, usage->buf,
		   usage->size);
	asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
	return true;
}

bool nPAClient::getCertificateDescriptionRaw(
	nPADataBuffer_t &certificateDescriptionRaw)
{
	certificateDescriptionRaw.pDataBuffer = new unsigned char[m_Idp->getCertificateDescription().size()];

	if (0x00 == certificateDescriptionRaw.pDataBuffer)
		return false;

	certificateDescriptionRaw.bufferSize =
		m_Idp->getCertificateDescription().size();
	memcpy(certificateDescriptionRaw.pDataBuffer,
			m_Idp->getCertificateDescription().data(),
			certificateDescriptionRaw.bufferSize);
	return true;
}

bool nPAClient::getServiceName(
	nPADataBuffer_t &serviceName)
{
	CertificateDescription_t *certificateDescription_ = 0x00;

	if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_,
				   m_Idp->getCertificateDescription().data(), m_Idp->getCertificateDescription().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getServiceName - Could not parse certificate description.");
		asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
		return false;
	}

	serviceName.pDataBuffer = new unsigned char[certificateDescription_->subjectName.size];

	if (0x00 == serviceName.pDataBuffer)
		return false;

	serviceName.bufferSize = certificateDescription_->subjectName.size;
	memcpy(serviceName.pDataBuffer, certificateDescription_->subjectName.buf,
		   serviceName.bufferSize);
	asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	return true;
}

bool nPAClient::getServiceURL(
	nPADataBuffer_t &serviceURL)
{
	CertificateDescription_t *certificateDescription_ = 0x00;

	if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_,
				   m_Idp->getCertificateDescription().data(), m_Idp->getCertificateDescription().size()).code != RC_OK) {
		eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getServiceURL - Could not parse certificate description.");
		asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
		return false;
	}

	if (0x00 == certificateDescription_->subjectURL) {
		asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
		return false;
	}

	serviceURL.pDataBuffer = new unsigned char[certificateDescription_->subjectURL->size];

	if (0x00 == serviceURL.pDataBuffer)
		return false;

	serviceURL.bufferSize = certificateDescription_->subjectURL->size;
	memcpy(serviceURL.pDataBuffer, certificateDescription_->subjectURL->buf,
		   serviceURL.bufferSize);
	asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	return true;
}

bool nPAClient::passwordIsRequired(void) const
{
	if (!m_hCard)
		return false;

	// Try to get ePA card
	ePACard &ePA_ = dynamic_cast<ePACard &>(*m_hCard);
	return !(ePA_.getSubSystem()->supportsPACE());
}

NPACLIENT_ERROR nPAClient::performPACE(
	const nPADataBuffer_t *const password,
	const struct chat *chatSelectedByUser,
	const nPADataBuffer_t *const certificateDescription)
{
	// Check the state of the protocol. We can only run PACE if the
	// protocol is in the unauthenticated state.
	if (Unauthenticated != m_protocolState)
		return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

	PaceInput pace_input;

	if (!chatSelectedByUser)
		return NPACLIENT_ERROR_INVALID_PARAMETER2;

	if (!certificateDescription)
		return NPACLIENT_ERROR_INVALID_PARAMETER3;

	// Actually we running the PACE protocol
	m_protocolState = PACE_Running;

	/* FIXME use an other type of secret... */
	pace_input.set_pin_id(PaceInput::pin);
	if (password)
		pace_input.set_pin(std::vector<unsigned char> (password->pDataBuffer,
					password->pDataBuffer + password->bufferSize));

	pace_input.set_certificate_description(std::vector<unsigned char>
			(certificateDescription->pDataBuffer,
			 certificateDescription->pDataBuffer + certificateDescription->bufferSize));

	if (!encode_CertificateHolderAuthorizationTemplate_t(chatSelectedByUser, m_chatUsed))
		return NPACLIENT_ERROR_INVALID_PARAMETER2;
	pace_input.set_chat(m_chatUsed);

	// Running the protocol
	ECARD_STATUS status = ECARD_SUCCESS;

	if ((status = m_clientProtocol->PACE(pace_input)) != ECARD_SUCCESS) {
		// @TODO: Do logging ...
		return NPACLIENT_ERROR_PACE_FAILED;
	}

	// PACE runs successfully
	m_protocolState = PACE_Done;
	// @TODO: Do logging ...
	return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::performTerminalAuthentication(
	void)
{
	std::vector<unsigned char> idPICC;
	std::vector<std::vector<unsigned char> > list_certificates;

	// Check the state of the protocol. We can only run TA if the
	// PACE protocol is done.
	if (PACE_Done != m_protocolState)
		return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

	m_protocolState = TA_Running;
	std::vector<unsigned char> idPICC_;
	m_clientProtocol->GetIDPICC(idPICC_);
	idPICC = idPICC_;

	if (!m_hCard)
		return ECARD_ERROR;

	// Try to get ePA card
	ePACard &ePA_ = dynamic_cast<ePACard &>(*m_hCard);

	if (!m_Idp->getTerminalAuthenticationData(ePA_.get_ef_cardaccess(), m_chatUsed, m_clientProtocol->GetCARCVCA(), idPICC, list_certificates,
			m_Puk_IFD_DH_CA)) {
		return NPACLIENT_ERROR_TA_INITIALIZATION_FAILD;
	}

	std::vector<unsigned char> termCertificate = m_Idp->getTerminalCertificate();
	std::vector<unsigned char> authenticatedAuxiliaryData = m_Idp->getAuthenticatedAuxiliaryData();
	std::vector<unsigned char> termDummy = termCertificate;
	std::vector<unsigned char> terminalCertificate_;
	terminalCertificate_ = termDummy;
	std::vector<unsigned char> authenticatedAuxiliaryDataDummy = authenticatedAuxiliaryData;
	std::vector<unsigned char> authenticatedAuxiliaryData_;

	if (authenticatedAuxiliaryDataDummy.size() > 0) {
		authenticatedAuxiliaryData_ = authenticatedAuxiliaryDataDummy;

	} else {
		authenticatedAuxiliaryData_.clear();
	}

	// Used in TA and CA
	std::vector<unsigned char> Puk_IFD_DH_;
	Puk_IFD_DH_ = m_Puk_IFD_DH_CA;
	// Only used in CA
	std::vector<unsigned char> toBeSigned_;
	ECARD_STATUS status = ECARD_SUCCESS;

	// Run the Terminal authentication until the signature action.
	if ((status = m_clientProtocol->TerminalAuthentication(list_certificates,
				  terminalCertificate_, Puk_IFD_DH_, authenticatedAuxiliaryData_, toBeSigned_)) != ECARD_SUCCESS) {
		return NPACLIENT_ERROR_TA_FAILED;
	}

	std::vector<unsigned char> toBeSigned;
	std::vector<unsigned char> signature;
	toBeSigned = toBeSigned_;

	if (!m_Idp->createSignature(toBeSigned, signature))
		return NPACLIENT_ERROR_CREATE_SIGNATURE_ERROR;

	std::vector<unsigned char> sendSignature_;
	sendSignature_ = signature;

	if ((status = m_clientProtocol->SendSignature(sendSignature_)) != ECARD_SUCCESS) {
		return NPACLIENT_ERROR_SEND_SIGNATURE_ERROR;
	}

	// Terminal Authentication runs successfully
	m_protocolState = TA_Done;
	// @TODO: Do logging ...
	return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::performChipAuthentication(
	void)
{
	ECARD_STATUS status = ECARD_SUCCESS;

	if (!m_hCard)
		return ECARD_ERROR;

	// Try to get ePA card
	ePACard &ePA_ = dynamic_cast<ePACard &>(*m_hCard);

	if (TA_Done != m_protocolState)
		return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

	const vector<unsigned char> ef_cardsecurity = ePA_.get_ef_cardsecurity();
	std::vector<unsigned char> GeneralAuthenticationResult;

	if ((status = m_clientProtocol->ChipAuthentication(m_Puk_IFD_DH_CA,
				  GeneralAuthenticationResult)) != ECARD_SUCCESS) {
		return NPACLIENT_ERROR_CA_FAILED;
	}

	std::vector<unsigned char> GAResult;
	GAResult = GeneralAuthenticationResult;

	if (!m_Idp->finalizeAuthentication(ef_cardsecurity, GAResult, m_capdus)) {
		return NPACLIENT_ERROR_CA_SERVER_FAILED;
	}

	m_protocolState = Authenticated;
	// @TODO: Do logging ...
	return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR nPAClient::readAttributed(void)
{
	if (Authenticated != m_protocolState)
		return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

	try {
		m_rapdus = m_hCard->transceive(m_capdus);

	} catch (...) {
		return NPACLIENT_ERROR_TRANSMISSION_ERROR;
	}

	std::string attributes;

	if (!m_Idp->readAttributes(m_rapdus))
		return NPACLIENT_ERROR_READ_FAILED;

	m_Idp->close();
	m_protocolState = Finished;
	return NPACLIENT_ERROR_SUCCESS;
}
