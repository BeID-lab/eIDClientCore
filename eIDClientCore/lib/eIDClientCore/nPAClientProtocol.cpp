/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "eCardCore/eCardStatus.h"
#include "nPAClientProtocol.h"
#include <debug.h>

/**
 */
ePAClientProtocol::ePAClientProtocol(
	ICard *hCard) : m_hCard(hCard)
{
}

ePAClientProtocol::~ePAClientProtocol(
	void)
{
}

/**
 */
ECARD_STATUS ePAClientProtocol::PACE(
	const PaceInput &pace_input)
{
	ECARD_STATUS status_ = ECARD_SUCCESS;
	// Setup output variables
	std::vector<unsigned char> car_cvca_;

	if (!m_hCard)
		return ECARD_ERROR;

	// Try to get ePA card
	ePACard &ePA_ = dynamic_cast<ePACard &>(*m_hCard);

	// Run the PACE protocol.
	if (ECARD_SUCCESS != (status_ = ePAPerformPACE(ePA_, pace_input,
									car_cvca_, m_idPICC, m_ca_oid)))
		return status_;

	// Copy the PACE results for further usage.
	m_carCVCA = std::string(car_cvca_.begin(), car_cvca_.end());

	return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::TerminalAuthentication(
	const std::vector<std::vector<unsigned char> >& list_certificates,
	const std::vector<unsigned char>& terminalCertificate,
	const std::vector<unsigned char>& PuK_IFD_DH_CA,
	const std::vector<unsigned char>& authenticatedAuxiliaryData,
	std::vector<unsigned char>& toBeSigned)
{
	std::vector<unsigned char> carCVCA_;
	carCVCA_ = std::vector<unsigned char> (m_carCVCA.begin(), m_carCVCA.end());

	if (!m_hCard)
		return ECARD_ERROR;

	// Try to get ePA card
	ePACard &ePA_ = dynamic_cast<ePACard &>(*m_hCard);

	// Run the CA protocol.
	return ePAPerformTA(ePA_, carCVCA_, list_certificates, terminalCertificate,
						m_ca_oid, PuK_IFD_DH_CA, authenticatedAuxiliaryData, toBeSigned);
}

/**
 */
ECARD_STATUS ePAClientProtocol::SendSignature(
	const std::vector<unsigned char>& signature)
{
	if (!m_hCard)
		return ECARD_ERROR;

	return ePASendSignature(*m_hCard, signature);
}

/**
 */
ECARD_STATUS ePAClientProtocol::ChipAuthentication(
	const std::vector<unsigned char>& Puk_IFD_DH,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	ECARD_STATUS status_ = ECARD_SUCCESS;

	if (!m_hCard)
		return ECARD_ERROR;

	if (ECARD_SUCCESS != (status_ = ePAPerformCA(*m_hCard, m_ca_oid, Puk_IFD_DH, GeneralAuthenticationResult)))
		return status_;

	return ECARD_SUCCESS;
}

ECARD_STATUS ePAClientProtocol::GetIDPICC(
	std::vector<unsigned char>& idPICC)
{
	idPICC = m_idPICC;
	return ECARD_SUCCESS;
}
