/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include <string.h>


#include "eIDECardClient.h"
#include "eIDUtils.h"
#include <debug.h>


eIdECardClient *eIdECardClient::m_instance = 0x00;

static string Byte2Hex(const unsigned char *bytes, size_t numBytes)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	size_t      i;
	string      strReturn("");

	for (i = 0; i < numBytes; i++) {
		const unsigned char c = bytes[i];
		strReturn.push_back(hexdigits[(c >> 4) & 0x0F]);
		strReturn.push_back(hexdigits[(c) & 0x0F]);
	}

	return strReturn;
}

static const vector<unsigned char> Hex2Byte(const char *str, size_t numBytes)
{
	vector<unsigned char>   vecRet;
	size_t                  i;
	size_t                  strLen;
	strLen = strnlen(str, numBytes);
	vecRet.clear();

	for (i = 0; i < strLen; i += 2) {
		char            c[3];
		unsigned char   uc = 0x00;
		c[0] = str[i];
		c[1] = str[i + 1];
		c[2] = 0x00;
		uc = 0xFF & strtoul(&c[0], NULL, 16);
		vecRet.push_back(uc);
	}

	return vecRet;
}

eIdECardClient::eIdECardClient()
{
	m_instance = 0x00;
	m_strSessionIdentifier = "";
	m_strPathSecurityParameter = "";
	m_strMessageID = "";
	m_strRequiredChat = "";
	m_strOptionalChat = "";
	m_strAuxiliaryData = "";
	m_strCertificateDescription = "";
	m_strEphemeralPublicKey = "";
	m_strSignature = "";
	m_strCurrentTag = "";
	m_strSessionIdentifier = "";
	m_hConnection = 0x00;
}

eIdECardClient::eIdECardClient(CharMap *paraMap)
{
	m_instance = 0x00;
	m_strSessionIdentifier = "";
	m_strPathSecurityParameter = "";
	m_strMessageID = "";
	m_strRequiredChat = "";
	m_strOptionalChat = "";
	m_strAuxiliaryData = "";
	m_strCertificateDescription = "";
	m_strEphemeralPublicKey = "";
	m_strSignature = "";
	m_strCurrentTag = "";
	m_strSessionIdentifier = "";
	m_hConnection = 0x00;
	m_strServerAddress = "";
	CharMapIt   it;
	it = paraMap->find((char *) "ServerAddress");

	if (it != paraMap->end()) {
		if (it->second != 0x00) {
			if (*(it->second) != 0x00)
				m_strServerAddress = *(it->second);
		}
	}

	it = paraMap->find((char *) "SessionIdentifier");

	if (it != paraMap->end()) {
		if (it->second != 0x00) {
			if (*(it->second) != 0x00)
				m_strSessionIdentifierN = *(it->second);
		}
	}

	it = paraMap->find((char *) "PathSecurity-Parameters");

	if (it != paraMap->end()) {
		if (it->second != 0x00) {
			if (*(it->second) != 0x00)
				m_strPathSecurityParameter = *(it->second);
		}
	}
}

eIdECardClient::~eIdECardClient(void)
{
	m_instance = 0x00;
}

/*
 *
 */
eIdECardClient *eIdECardClient::createInstance(
	CharMap *paraMap)
{
	if (0x00 == m_instance)
		m_instance = new eIdECardClient(paraMap);

	return m_instance;
}


bool eIdECardClient::open(void)
{
	return StartConnection(m_strServerAddress.c_str(), m_strSessionIdentifierN, m_strPathSecurityParameter);
}

/*
 *
 */
bool eIdECardClient::close()
{
	EndConnection();
	return true;
}


/*
 *
 */
NPACLIENT_ERROR eIdECardClient::initialize(
	IClient *pClient)
{
	m_pClient = pClient;
	string reqCHAT = "";
	string optCHAT = "";
	string authAux = "";
	string cert = "";
	string certDesc = "";
	string strNewMessageID = "";
	StartPAOS(m_strSessionIdentifier, reqCHAT, optCHAT, authAux, cert, certDesc, strNewMessageID);
	m_TerminalCertificate = Hex2Byte(cert.c_str(), cert.length());
	m_CertificateDescription = Hex2Byte(certDesc.c_str(), certDesc.length());
	m_RequiredCHAT = Hex2Byte(reqCHAT.c_str(), reqCHAT.length());
	m_OptionalCHAT = Hex2Byte(optCHAT.c_str(), optCHAT.length());
	m_AuthenticatedAuxiliaryData = Hex2Byte(authAux.c_str(), authAux.length());
	m_strLastMsgUUID = strNewMessageID;

	if (m_TerminalCertificate.empty()) {
		eCardCore_debug(DEBUG_LEVEL_PAOS, "No Terminal Certificate\n");
		return NPACLIENT_ERROR_NO_TERMINAL_CERTIFICATE;
	}

	if (m_CertificateDescription.empty()) {
		eCardCore_debug(DEBUG_LEVEL_PAOS, "No Terminal CertificateDescription\n");
		return NPACLIENT_ERROR_NO_CERTIFICATE_DESCRIPTION;
	}

	hexdump(DEBUG_LEVEL_PAOS, "StartPAOS Cert:    ", &m_TerminalCertificate[0], m_TerminalCertificate.size());
	hexdump(DEBUG_LEVEL_PAOS, "StartPAOS CDesc:   ", &m_CertificateDescription[0], m_CertificateDescription.size());

	if (!m_RequiredCHAT.empty())
		hexdump(DEBUG_LEVEL_PAOS, "StartPAOS RCHAT:   ", &m_RequiredCHAT[0], m_RequiredCHAT.size());

	if (!m_OptionalCHAT.empty())
		hexdump(DEBUG_LEVEL_PAOS, "StartPAOS OCHAT:   ", &m_OptionalCHAT[0], m_OptionalCHAT.size());

	if (!m_AuthenticatedAuxiliaryData.empty())
		hexdump(DEBUG_LEVEL_PAOS, "StartPAOS AuthAux: ", &m_AuthenticatedAuxiliaryData[0], m_AuthenticatedAuxiliaryData.size());

	if (!m_strLastMsgUUID.empty())
		hexdump(DEBUG_LEVEL_PAOS, "StartPAOS MsgUUID: ", &m_strLastMsgUUID[0], m_strLastMsgUUID.size());

	return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
bool eIdECardClient::getTerminalAuthenticationData(
	const std::vector<unsigned char>& efCardAccess,
	const std::vector<unsigned char>& chat,
	const std::string &cvCACHAR,
	const std::vector<unsigned char>& idPICC,
	std::vector<std::vector<unsigned char> >& list_certificates,
	std::vector<unsigned char>& x_Puk_IFD_DH_CA_,
	std::vector<unsigned char>& y_Puk_IFD_DH_CA_
)
{
	string myEFCardAccess = Byte2Hex(&efCardAccess[0], efCardAccess.size());
	string myIDPICC = Byte2Hex(&idPICC[0], idPICC.size());
	string myChat = Byte2Hex(&chat[0], chat.size());
	std::vector<unsigned char> reqChat = m_RequiredCHAT;
	string myReqChat = Byte2Hex(&reqChat[0],  reqChat.size());
	hexdump(DEBUG_LEVEL_PAOS, "IDPICC", (void *) myIDPICC.c_str(), myIDPICC.size());
	hexdump(DEBUG_LEVEL_PAOS, "used Chat", (void *) myChat.c_str(), myChat.size());
	string ephPubKey = "";
	certificateList_t CertList;
	string strNewMessageID = "";
	PACEResponse(m_strLastMsgUUID, myChat, cvCACHAR, myEFCardAccess, myIDPICC, ephPubKey, CertList, strNewMessageID);
	m_strLastMsgUUID = strNewMessageID;
	string cert1;

	while (!CertList.empty()) {
		cert1 = CertList.front();
		CertList.pop_front();
		std::vector<unsigned char> myCert = Hex2Byte(cert1.c_str(), cert1.length());
		list_certificates.push_back(myCert);
	}

	std::vector<unsigned char> myKey = Hex2Byte(ephPubKey.c_str(), ephPubKey.size());

	if (myKey.empty()) return false;

	hexdump(DEBUG_LEVEL_PAOS, "ephPubKey", &myKey[0], ephPubKey.size() / 2);

	if (!(cert1.length() % 2 == 0)) return false;

	if (!(ephPubKey.size() % 4 == 0)) return false;

	size_t half = ephPubKey.size() / 4;

	for (size_t i = 0; i < half; i++)
		x_Puk_IFD_DH_CA_.push_back(myKey[i]);

	for (size_t i = 0; i < half; i++)
		y_Puk_IFD_DH_CA_.push_back(myKey[i + half]);

	return true;
}

/**
 *
 */
bool eIdECardClient::createSignature(
	std::vector<unsigned char> toBeSigned,
	std::vector<unsigned char>& signature)
{
	string challenge = Byte2Hex(&toBeSigned[0], toBeSigned.size());
	string retSignature = "";
	string strNewMessageID = "";
	TAResponse(m_strLastMsgUUID, challenge, retSignature, strNewMessageID);
	m_strLastMsgUUID = strNewMessageID;
	std::vector<unsigned char> mySig = Hex2Byte(retSignature.c_str(), retSignature.length());
	signature = mySig;
	return true;
}

/*
 *
 */
bool eIdECardClient::finalizeAuthentication(
	std::vector<unsigned char> efCardSecurity,
	std::vector<unsigned char> GAResult,
	std::vector<CAPDU>& apdus)
{
	string myEFCardSecurity = Byte2Hex(&efCardSecurity[0], efCardSecurity.size());
	string myAuthToken = Byte2Hex(&GAResult[4 + 8 + 2], 8);
	string myNonce = Byte2Hex(&GAResult[4], 8);
	APDUList_t  myAPDUList;
	string strNewMessageID = "";
	CAResponse(m_strLastMsgUUID, myEFCardSecurity, myAuthToken, myNonce, myAPDUList, strNewMessageID);
	m_strLastMsgUUID = strNewMessageID;
	apdus.clear();

	for (list<string>::iterator it = myAPDUList.begin(); it != myAPDUList.end(); ++it) {
		string strAPDU = *it;
		std::vector<unsigned char> myAPDU = Hex2Byte(strAPDU.c_str(), strAPDU.length());
		apdus.push_back(myAPDU);
	}

	return true;
}

bool eIdECardClient::readAttributes(
	std::vector<RAPDU>& rapdus)
{
	APDUList_t  outAPDUList;
	APDUList_t  inAPDUList;
	inAPDUList.clear();
	vector<unsigned char> rapdu;

	for (size_t i = 0; i < rapdus.size(); ++i) {
		rapdu = rapdus.at(i).asBuffer();
		string strAPDU = Byte2Hex(&rapdu[0], rapdu.size());
		inAPDUList.push_back(strAPDU);
	}

	TransmitResponse(m_strLastMsgUUID, inAPDUList, outAPDUList);
	return true;
}

bool eIdECardClient::StartConnection(const char *url, const string &strSessionIdentifier, const string &strPSKKey)
{
	m_strSessionIdentifier = strSessionIdentifier;
	parse_url(url);

	if (strPSKKey.length() > 0) {
		size_t pos1, pos2;
		pos1 = strPSKKey.find("<PSK>");
		pos1 += 5;
		pos2 = strPSKKey.find("</PSK>");

		//PSK-Tags gefunden
		if (string::npos != pos1 && string::npos != pos2) {
			std::string strPSKKeyTmp = strPSKKey.substr(pos1, pos2 - pos1);
			EID_CLIENT_CONNECTION_ERROR rVal = eIDClientConnectionStart(&m_hConnection, m_strHostname.c_str(), m_strPort.c_str(), strSessionIdentifier.c_str(), strPSKKeyTmp.c_str());

			if (rVal != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
				eCardCore_warn(DEBUG_LEVEL_PAOS, "eIDClientConnectionStart failed (0x%08X)", rVal);
				return false;
			}

		} else {
			EID_CLIENT_CONNECTION_ERROR rVal = eIDClientConnectionStart(&m_hConnection, m_strHostname.c_str(), m_strPort.c_str(), strSessionIdentifier.c_str(), strPSKKey.c_str());

			if (rVal != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
				eCardCore_warn(DEBUG_LEVEL_PAOS, "eIDClientConnectionStart failed (0x%08X)", rVal);
				return false;
			}
		}

	} else {
		EID_CLIENT_CONNECTION_ERROR rVal = eIDClientConnectionStart(&m_hConnection, m_strHostname.c_str(), m_strPort.c_str(), strSessionIdentifier.c_str(), NULL);

		if (rVal != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			eCardCore_warn(DEBUG_LEVEL_PAOS, "eIDClientConnectionStart failed (0x%08X)", rVal);
			return false;
		}
	}

	if (m_hConnection == 0x00) {
		eCardCore_warn(DEBUG_LEVEL_PAOS, "m_hConnection == 0x00 (%s:%d)", __FILE__, __LINE__);
		return false;
	}

	return true;
}

void eIdECardClient::EndConnection()
{
	eIDClientConnectionEnd(m_hConnection);
}

// send a HTTP POST request
string eIdECardClient::request_post(const string &in)
{
	string  strParam = "sessionid=" + m_strSessionIdentifier;
	char    buf[10000];
	memset(&buf[0], 0x00, 10000);
	//  string  strReceive;
	size_t     len = in.length();
	ostringstream buffer;
	buffer << "POST" << " " << m_strPath.c_str() << "/?" << strParam << " HTTP/1.1\r\n";
	buffer << "Content-Length: " << len << "\r\n";
	buffer << "Accept: text/html; application/vnd.paos+xml\r\n";
	buffer << "PAOS: ver=\"urn:liberty:2006-08\";http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand\r\n";
	buffer << "Host: " << m_strHostname.c_str() << ":" <<  m_strPort.c_str() << "\r\n";
	buffer << "\r\n";

	if (len > 0) {
		buffer << in;
	}

	const string   &strToSend = buffer.str();

	eIDClientConnectionSendRequest(m_hConnection, strToSend.c_str(), &buf[0], 10000);

	string strResult;

	strResult.append(&buf[0]);

	string  strContent = "";

	string  strLength = "";

	int     content_length = 0;

	size_t pos1 = 0;

	size_t pos2 = 0;

	if (((pos1 = strResult.find("Content-Length:")) != string::npos) || ((pos1 = strResult.find("content-length:")) != string::npos)) {
		pos2 = strResult.find_first_of('\n', pos1 + 15);

		if (pos2 > 0) {
			strLength = strResult.substr(pos1 + 15, pos2 - pos1 - 15);
			content_length = atoi(strLength.c_str());
		}
	}

	strContent = strResult.substr(strResult.length() - content_length);
	return strContent;
}

// send a HTTP GET with PAOS-header
string eIdECardClient::request_get_PAOS()
{
	string  strParam = "sessionid=" + m_strSessionIdentifier;
	char    buf[10000];
	memset(&buf[0], 0x00, 10000);
	string  strReceive;
	ostringstream buffer;
	buffer << "GET" << " " << m_strPath.c_str() << " HTTP/1.1\r\n";
	buffer << "Accept: text/html; application/vnd.paos+xml\r\n";
	buffer << "PAOS: ver=\"urn:liberty:2006-08\";http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand\r\n";
	buffer << "Host: " << m_strHostname.c_str() << ":" << m_strPort.c_str() << "\r\n";
	buffer << "\r\n";
	const string   &strToSend = buffer.str();
	//  eIDClientConnectionSendRequest(m_hConnection, "GET", strParam.c_str(), NULL, &buf[0], 10000);
	eIDClientConnectionSendRequest(m_hConnection, strToSend.c_str(), &buf[0], 10000);
	string strResult;
	strResult.append(&buf[0]);
	string  strContent = "";
	string  strLength = "";
	int     content_length = 0;
	size_t pos1 = 0;
	size_t pos2 = 0;

	if (((pos1 = strResult.find("Content-Length:")) != string::npos) || ((pos1 = strResult.find("content-length:")) != string::npos)) {
		pos2 = strResult.find_first_of('\n', pos1 + 15);

		if (pos2 > 0) {
			strLength = strResult.substr(pos1 + 15, pos2 - pos1 - 15);
			content_length = atoi(strLength.c_str());
		}
	}

	strContent = strResult.substr(strResult.length() - content_length);
	return strContent;
}

void eIdECardClient::StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs)
{
	eIdECardClient *pThis = (eIdECardClient *) pUserData;
	pThis->OnStartElement(pszName);
}

void eIdECardClient::EndElementHandler(void *pUserData, const XML_Char *pszName)
{
	eIdECardClient *pThis = (eIdECardClient *) pUserData;
	pThis->OnEndElement();
}

void eIdECardClient::CharacterDataHandler(void *pUserData, const XML_Char *pszData, int nLength)
{
	eIdECardClient *pThis = (eIdECardClient *) pUserData;
	pThis->OnCharacterData(pszData, nLength);
}

void eIdECardClient::OnStartElement(const XML_Char *pszName)
{
	m_strCurrentTag = string(pszName);
	return;
}

void eIdECardClient::OnEndElement(void)
{
	m_strCurrentTag = "";
	return;
}

void eIdECardClient::OnCharacterData(const XML_Char *pszData, size_t nLength)
{
	if (m_strCurrentTag.find("CertificateDescription") != string::npos) {
		m_strCertificateDescription = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "CertificateDescription : %s", m_strCertificateDescription.c_str());

	} else if (m_strCurrentTag.find("RequiredCHAT") != string::npos) {
		m_strRequiredChat = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "RequiredCHAT : %s", m_strRequiredChat.c_str());

	} else if (m_strCurrentTag.find("AuthenticatedAuxiliaryData") != string::npos) {
		m_strAuxiliaryData = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "AuthenticatedAuxiliaryData : %s", m_strAuxiliaryData.c_str());

	} else if (m_strCurrentTag.find("EphemeralPublicKey") != string::npos) {
		m_strEphemeralPublicKey = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "EphemeralPublicKey : %s", m_strEphemeralPublicKey.c_str());

	} else if (m_strCurrentTag.find("Certificate") != string::npos) {
		string  strCert = string(pszData, nLength);
		m_certificateList.push_back(strCert);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "Certificate : %s", strCert.c_str());

	} else if (m_strCurrentTag.find("Signature") != string::npos) {
		m_strSignature = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "Signature : %s", m_strSignature.c_str());

	} else if (m_strCurrentTag.find("InputAPDU") != string::npos) {
		string  strAPDU = string(pszData, nLength);
		m_APDUList.push_back(strAPDU);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "InputAPDU : %s", strAPDU.c_str());

	} else if (m_strCurrentTag.find("MessageID") != string::npos) {
		m_strMessageID = string(pszData, nLength);
		eCardCore_debug(DEBUG_LEVEL_PAOS, "MessageID : %s", m_strMessageID.c_str());
	}

	return;
}

void eIdECardClient::WritePAOS_Response(::stringstream &oss, stringstream &ss, const string &strRelatesTo)
{
	string           strUrnMessageID("urn:uuid");
	strUrnMessageID += getRandomStringID(40);
	oss << "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">";
	oss << "<S:Header xmlns:A=\"http://www.w3.org/2005/03/addressing\">";
	oss << "<PAOS S:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" S:mustUnderstand=\"1\" xmlns=\"urn:liberty:paos:2006-08\">";
	oss << "<Version>urn:liberty:2006-08</Version>";
	oss << "<EndpointReference>";
	oss << "<Address>http://www.projectliberty.org/2006/01/role/paos</Address>";
	oss << "<MetaData><ServiceType>http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand</ServiceType></MetaData>";
	oss << "</EndpointReference>";
	oss << "</PAOS>";
	oss << "<A:RelatesTo>" << strRelatesTo.c_str() << "</A:RelatesTo>";
	oss << "<A:ReplyTo><A:Address>http://www.projectlibrary.org/2006/02/role/paos</A:Address></A:ReplyTo>";
	oss << "<A:MessageID>" << strUrnMessageID.c_str() << "</A:MessageID>";
	oss << "</S:Header>";
	oss << "<S:Body>" << ss.str() << "</S:Body>";
	oss << "</S:Envelope>";
	string strTest = oss.str();
}

void eIdECardClient::WriteStartPaos(::stringstream &oss, const string &strSessionID)
{
	string       strContextHandle = getRandomStringID(40);
	string       strSlotHandle = getRandomStringID(40);
	string       strUrnMessageID("urn:uuid");
	strUrnMessageID += getRandomStringID(40);
	oss << "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">";
	oss << "<S:Header xmlns:A=\"http://www.w3.org/2005/03/addressing\">";
	oss << "<PAOS S:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" S:mustUnderstand=\"1\" xmlns=\"urn:liberty:paos:2006-08\">";
	oss << "<Version>urn:liberty:2006-08</Version>";
	oss << "<EndpointReference>";
	oss << "<Address>http://www.projectliberty.org/2006/01/role/paos</Address>";
	oss << "<MetaData><ServiceType>http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand</ServiceType></MetaData>";
	oss << "</EndpointReference>";
	oss << "</PAOS>";
	oss << "<A:MessageID>" << strUrnMessageID.c_str() << "</A:MessageID>";
	oss << "<A:ReplyTo><A:Address>http://www.projectlibrary.org/2006/02/role/paos</A:Address></A:ReplyTo>";
	oss << "</S:Header>";
	oss << "<S:Body>";
	oss << "<StartPAOS xmlns=\"urn:iso:std:iso-iec:24727:tech:schema\">";
	oss << "<SessionIdentifier>" << strSessionID.c_str() << "</SessionIdentifier>";
	oss << "<ConnectionHandle>";
	oss << "<ContextHandle>" << strContextHandle.c_str() << "</ContextHandle>";
	oss << "<SlotHandle>" << strSlotHandle.c_str() << "</SlotHandle>";
	oss << "</ConnectionHandle>";
	oss << "</StartPAOS>";
	oss << "</S:Body>";
	oss << "</S:Envelope>";
	//   string strTest = oss.str();
}

void eIdECardClient::WriteDIDAuthenticateResponse(::stringstream &oss, stringstream &ssOutputType, const string &strMessageID)
{
	stringstream ss(std::stringstream::out);
	ss << "<iso:DIDAuthenticateResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:iso=\"urn:iso:std:iso-iec:24727:tech:schema\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" >";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << ssOutputType.str();
	ss << "</iso:DIDAuthenticateResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void eIdECardClient::WriteEAC1Output(::stringstream &oss, const string &strMessageID, const string &strUserChat, const string &strCertRef, const string &strEFCardAccess, const string &strIDPICC)
{
	stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC1OutputType\">";
	ss << "<iso:RetryCounter>3</iso:RetryCounter>";
	ss << "<iso:CertificateHolderAuthorizationTemplate>" << strUserChat.c_str() << "</iso:CertificateHolderAuthorizationTemplate>";
	ss << "<iso:CertificationAuthorityReference>" << strCertRef.c_str() << "</iso:CertificationAuthorityReference>";
	ss << "<iso:EFCardAccess>" << strEFCardAccess.c_str() << "</iso:EFCardAccess>";
	ss << "<iso:IDPICC>" << strIDPICC.c_str() << "</iso:IDPICC>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void eIdECardClient::WriteEAC2OutputChallenge(::stringstream &oss, const string &strMessageID, const string &strChallenge)
{
	stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC2OutputType\">";
	ss << "<iso:Challenge>" << strChallenge.c_str() << "</iso:Challenge>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void eIdECardClient::WriteEAC2OutputCardSecurity(::stringstream &oss, const string &strMessageID, const string &strEFCardSecurity, const string &strAuthenticationToken, const string &strNonce)
{
	stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC2OutputType\">";
	ss << "<iso:EFCardSecurity>" << strEFCardSecurity.c_str() << "</iso:EFCardSecurity>";
	ss << "<iso:AuthenticationToken>" << strAuthenticationToken.c_str() << "</iso:AuthenticationToken>";
	ss << "<iso:Nonce>" << strNonce.c_str() << "</iso:Nonce>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void eIdECardClient::WriteTransmitResponse(::stringstream &oss, stringstream &ssOutputAPDU, const string &strMessageID)
{
	stringstream ss(std::stringstream::out);
	ss << "<iso:TransmitResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:iso=\"urn:iso:std:iso-iec:24727:tech:schema\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\">";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << ssOutputAPDU.str();
	ss << "</iso:TransmitResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void eIdECardClient::WriteInitializeFrameworkResponse(::stringstream &oss, const string &strMessageID)
{
	stringstream ss(std::stringstream::out);
	ss << "<ec:InitializeFrameworkResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:ec=\"http://www.bsi.bund.de/ecard/api/1.1\">";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << "<ec:Version>";
	ss << "<ec:Major>1</ec:Major>";
	ss << "<ec:Minor>3</ec:Minor>";
	ss << "<ec:SubMinor>0</ec:SubMinor>";
	ss << "</ec:Version>";
	ss << "</ec:InitializeFrameworkResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void eIdECardClient::WriteOutputAPDU(::stringstream &oss, const string &strMessageID, const APDUList_t &APDUList)
{
	stringstream ss(std::stringstream::out);

	for (list<string>::const_iterator it = APDUList.begin(); it != APDUList.end(); ++it) {
		string strAPDU = *it;
		ss << "<iso:OutputAPDU>" << strAPDU.c_str() << "</iso:OutputAPDU>";
	}

	WriteTransmitResponse(oss, ss, strMessageID);
}

bool eIdECardClient::doParse(const string &strXML)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) this);
	XML_SetStartElementHandler(parser, StartElementHandler);
	XML_SetEndElementHandler(parser, EndElementHandler);
	XML_SetCharacterDataHandler(parser, CharacterDataHandler);
	XML_Parse(parser, strXML.c_str(), strXML.length(), true);
	XML_ParserFree(parser);
	return true;
}

void eIdECardClient::StartPAOS(const string &strSessionID,
							   string &strRequiredChat,
							   string &strOptionalChat,
							   string &strAuxiliaryData,
							   string &strCertificate,
							   string &strCertificateDescription,
							   string &strNewMessageID)
{
	m_strMessageID = "";
	m_strRequiredChat = "";
	m_strOptionalChat = "";
	m_strAuxiliaryData = "";
	m_strCertificateDescription = "";
	m_certificateList.clear();
	stringstream ioss(std::stringstream::out);
	WriteStartPaos(ioss, strSessionID);
	string xml_str = ioss.str();
	string ret = request_post(xml_str);
	doParse(ret);
	stringstream iossFrame(std::stringstream::out);
	WriteInitializeFrameworkResponse(iossFrame, m_strMessageID);
	string xml_strFrame = iossFrame.str();
	string retFrame = request_post(xml_strFrame);
	doParse(retFrame);
	strRequiredChat = m_strRequiredChat;
	strOptionalChat = m_strOptionalChat;
	strAuxiliaryData = m_strAuxiliaryData;

	if (!m_certificateList.empty()) {
		strCertificate = m_certificateList.front();
	}

	strCertificateDescription = m_strCertificateDescription;
	strNewMessageID = m_strMessageID;
	return;
}

void eIdECardClient::PACEResponse(const string &strMessageID,
								  const string &strUserChat,
								  const string &strCertRef,
								  const string &strEFCardAccess,
								  const string &strIDPICC,
								  string &strEphemeralPublicKey,
								  certificateList_t &CertList,
								  string &strNewMessageID)
{
	m_strEphemeralPublicKey = "";
	m_certificateList.clear();
	stringstream ioss(std::stringstream::out);
	WriteEAC1Output(ioss, strMessageID, strUserChat, strCertRef, strEFCardAccess, strIDPICC);
	string xml_str = ioss.str();
	string ret = request_post(xml_str);
	doParse(ret);
	strEphemeralPublicKey = m_strEphemeralPublicKey;
	CertList = m_certificateList;
	strNewMessageID = m_strMessageID;
}

void eIdECardClient::TAResponse(const string &strMessageID,
								const string &strChallenge,
								string &strSignature,
								string &strNewMessageID)
{
	stringstream ioss(std::stringstream::out);
	WriteEAC2OutputChallenge(ioss, strMessageID, strChallenge);
	string xml_str = ioss.str();
	string ret = request_post(xml_str);
	doParse(ret);
	strSignature = m_strSignature;
	strNewMessageID = m_strMessageID;
}

void eIdECardClient::CAResponse(const string &strMessageID,
								const string &strEFCardSecurity,
								const string &strAuthenticationToken,
								const string &strNonce,
								APDUList_t &APDUList,
								string &strNewMessageID)
{
	m_APDUList.clear();
	stringstream ioss(std::stringstream::out);
	WriteEAC2OutputCardSecurity(ioss, strMessageID, strEFCardSecurity, strAuthenticationToken, strNonce);
	string xml_str = ioss.str();
	string ret = request_post(xml_str);
	doParse(ret);
	APDUList = m_APDUList;
	strNewMessageID = m_strMessageID;
}

void eIdECardClient::TransmitResponse(const string &strMessageID,
									  const APDUList_t &inAPDUList,
									  APDUList_t &outAPDUList)
{
	stringstream ioss(std::stringstream::out);
	WriteOutputAPDU(ioss, strMessageID, inAPDUList);
	string xml_str = ioss.str();
	string ret = request_post(xml_str);
	doParse(ret);
	outAPDUList.clear();
}

string eIdECardClient::getRandomStringID(size_t nCount)
{
	string  strRandomStringID;
	char *buffer = (char *) malloc(nCount + 1);
	memset(buffer, '\0', nCount + 1);
	vector<unsigned char> random_bytes;

	if (ECARD_SUCCESS != ePAGetRandom(nCount, random_bytes))
		return strRandomStringID;

	for (size_t i = 0; i < random_bytes.size(); i++) {
		int ran = random_bytes[i] % 16;

		if (ran < 10) {
			ran += 48;

		} else {
			ran += 87;
		}

		buffer[i] = (char) ran;
	}

	strRandomStringID = buffer;
	free(buffer);
	return strRandomStringID;
}

bool eIdECardClient::parse_url(const char *str, const char *default_port)
{
	if (!str || !*str)
		return false;

	const char *p1 = strstr(str, "://");

	if (p1) {
		m_strScheme.assign(str, p1 - str);
		p1 += 3;

	} else {
		p1 = str;
	}

	const char *p2 = strchr(p1, ':');

	//      const char* p3 = p2 ? strchr(p2+1, '/'): p2;
	const char *p3 = strchr(p1, '/');

	if (p2) {
		m_strHostname.assign(p1, p2 - p1);

		if (p3) {
			m_strPort.assign(p2 + 1, p3 - (p2 + 1));
			m_strPath = p3;

		} else {
			m_strPort.assign(p2 + 1);
		}

	} else {
		m_strPort = default_port;

		if (p3) {
			m_strHostname.assign(p1, p3 - p1);
			m_strPath = p3;

		} else {
			m_strHostname = p1;
		}
	}

	if (m_strPath.empty())
		m_strPath = "";

	return true;
}

