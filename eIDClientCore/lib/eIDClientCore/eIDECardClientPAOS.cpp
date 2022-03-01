/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#include <cstring>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define XML_STATIC
#include <expat.h>

#include "eIDECardClientPAOS.h"
#include "eIDClientConnection.h"

#include "nPA-EAC/nPAAPI.h"

typedef std::list<std::string> APDUList_t;
typedef std::list<std::string> certificateList_t;

class CParserObject
{
public:
    CParserObject()
    {
        
    }
    ~CParserObject()
    {
        
    }
    
    std::string  m_strCurrentTag;

    std::string  m_strRequiredChat;
    std::string  m_strOptionalChat;
    std::string  m_strAuxiliaryData;
    std::string  m_strCertificateDescription;
    std::string  m_strTransactionInfo;
    
    std::string              m_strEphemeralPublicKey;
    certificateList_t   m_certificateList;
    
    std::string  m_strSignature;
    
    std::string  m_strMessageID;
    
    APDUList_t          m_APDUList;
};

std::map<EIDCLIENT_CONNECTION_HANDLE, std::string>  g_mapMassageID;
typedef std::map<EIDCLIENT_CONNECTION_HANDLE, std::string>::iterator MapMessageIterator;

std::string  g_strMessageID("");


static std::string Byte2Hex(const unsigned char *bytes, size_t numBytes)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	size_t      i;
	std::string      strReturn("");
    
	for (i = 0; i < numBytes; i++) {
		const unsigned char c = bytes[i];
		strReturn.push_back(hexdigits[(c >> 4) & 0x0F]);
		strReturn.push_back(hexdigits[(c) & 0x0F]);
	}
    
	return strReturn;
}

static const std::vector<unsigned char> Hex2Byte(const char *str, size_t numBytes)
{
	std::vector<unsigned char>   vecRet;
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

std::string getRandomStringID(size_t nCount)
{
	std::string  strRandomStringID;
	std::vector<unsigned char> random_bytes;
    
	if (ECARD_SUCCESS != ePAGetRandom(nCount, random_bytes))
		return strRandomStringID;
    
	for (size_t i = 0; i < random_bytes.size(); i++) {
		int ran = random_bytes[i] % 16;
        
		if (ran < 10) {
			ran += 48;
            
		} else {
			ran += 87;
		}
        
		strRandomStringID.push_back(ran);
	}
    
	return strRandomStringID;
}

std::string getMessageID(const EIDCLIENT_CONNECTION_HANDLE hConnection)
{
//	return g_strMessageID;

    std::string strMessageID = "";
	MapMessageIterator it = g_mapMassageID.find(hConnection);

    if(it != g_mapMassageID.end())
    {
		strMessageID = it->second;
    }

    return strMessageID;
}

void setMessageID(const EIDCLIENT_CONNECTION_HANDLE hConnection, const std::string strMessageID)
{
    g_mapMassageID.erase(hConnection);
    g_mapMassageID.insert( std::pair<EIDCLIENT_CONNECTION_HANDLE, std::string>(hConnection,strMessageID) );

//	std::string strTest = getMessageID(hConnection);
//    g_strMessageID = strMessageID;
}

void removeMessageID(const EIDCLIENT_CONNECTION_HANDLE hConnection)
{
       g_mapMassageID.erase(hConnection);
}


void WritePAOS_Response(std::stringstream &oss, std::stringstream &ss, const std::string &strRelatesTo)
{
	//Similar structure as RelatesTo, which we got from the server.
	//std::string           strUrnMessageID("urn:uuid");
	//strUrnMessageID += getRandomStringID(40);
	std::string           strUrnMessageID("urn:uuid:");
	strUrnMessageID += getRandomStringID(8) + "-";
	strUrnMessageID += getRandomStringID(4) + "-";
	strUrnMessageID += getRandomStringID(4) + "-";
	strUrnMessageID += getRandomStringID(4) + "-";
	strUrnMessageID += getRandomStringID(12);
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
}

void WriteStartPaos(std::stringstream &oss, const std::string &strSessionID)
{
	std::string       strContextHandle = getRandomStringID(40);
	std::string       strSlotHandle = getRandomStringID(40);
	std::string       strUrnMessageID("urn:uuid");
	strUrnMessageID += getRandomStringID(40);
	oss << "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">";
	oss << "<S:Header xmlns:A=\"http://www.w3.org/2005/03/addressing\">";
	oss << "<PAOS S:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" S:mustUnderstand=\"1\" xmlns=\"urn:liberty:paos:2006-08\">";
	oss << "<Version>urn:liberty:2006-08</Version>";
	oss << "<EndpointReference>";
	oss << "<Address>http://www.projectliberty.org/2006/01/role/paos</Address>";
	oss << "<MetaData>";
	oss << "<ServiceType>http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand</ServiceType>";
	oss << "<Options/>";
	oss << "</MetaData>";
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
	oss << "<UserAgent>";
	oss << "<Name>eIDClientCore</Name>";
	oss << "<VersionMajor>10</VersionMajor>";
	oss << "<VersionMinor>90</VersionMinor>";
	oss << "<VersionSubminor>0</VersionSubminor>";
	oss << "</UserAgent>";
	oss << "</StartPAOS>";
	oss << "</S:Body>";
	oss << "</S:Envelope>";
}

void WriteDIDAuthenticateResponse(std::stringstream &oss, std::stringstream &ssOutputType, const std::string &strMessageID)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<iso:DIDAuthenticateResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:iso=\"urn:iso:std:iso-iec:24727:tech:schema\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" >";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << ssOutputType.str();
	ss << "</iso:DIDAuthenticateResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void WriteEAC1Output(std::stringstream &oss, const std::string &strMessageID, const std::string &strUserChat, const std::string &strCertRef, const std::string &strEFCardAccess, const std::string &strIDPICC, const std::string &strChallenge)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC1OutputType\">";
	ss << "<iso:RetryCounter>3</iso:RetryCounter>";
	ss << "<iso:CertificateHolderAuthorizationTemplate>" << strUserChat.c_str() << "</iso:CertificateHolderAuthorizationTemplate>";
	ss << "<iso:CertificationAuthorityReference>" << strCertRef.c_str() << "</iso:CertificationAuthorityReference>";
	ss << "<iso:EFCardAccess>" << strEFCardAccess.c_str() << "</iso:EFCardAccess>";
	ss << "<iso:IDPICC>" << strIDPICC.c_str() << "</iso:IDPICC>";
	ss << "<iso:Challenge>" << strChallenge.c_str() << "</iso:Challenge>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void WriteEAC2OutputChallenge(std::stringstream &oss, const std::string &strMessageID, const std::string &strChallenge)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC2OutputType\">";
	ss << "<iso:Challenge>" << strChallenge.c_str() << "</iso:Challenge>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void WriteEAC2OutputCardSecurity(std::stringstream &oss, const std::string &strMessageID, const std::string &strEFCardSecurity, const std::string &strAuthenticationToken, const std::string &strNonce)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<iso:AuthenticationProtocolData xsi:type=\"iso:EAC2OutputType\">";
	ss << "<iso:EFCardSecurity>" << strEFCardSecurity.c_str() << "</iso:EFCardSecurity>";
	ss << "<iso:AuthenticationToken>" << strAuthenticationToken.c_str() << "</iso:AuthenticationToken>";
	ss << "<iso:Nonce>" << strNonce.c_str() << "</iso:Nonce>";
	ss << "</iso:AuthenticationProtocolData>";
	WriteDIDAuthenticateResponse(oss, ss, strMessageID);
}

void WriteTransmitResponse(std::stringstream &oss, std::stringstream &ssOutputAPDU, const std::string &strMessageID)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<iso:TransmitResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:iso=\"urn:iso:std:iso-iec:24727:tech:schema\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\">";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << ssOutputAPDU.str();
	ss << "</iso:TransmitResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void WriteInitializeFrameworkResponse(std::stringstream &oss, const std::string &strMessageID)
{
	std::stringstream ss(std::stringstream::out);
	ss << "<ec:InitializeFrameworkResponse Profile=\"http://www.bsi.bund.com/ecard/api/1.1\" xmlns:dss=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:ec=\"http://www.bsi.bund.de/ecard/api/1.1\">";
	ss << "<dss:Result><dss:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</dss:ResultMajor></dss:Result>";
	ss << "<ec:Version>";
	ss << "<ec:Major>10</ec:Major>";
	ss << "<ec:Minor>90</ec:Minor>";
	ss << "<ec:SubMinor>0</ec:SubMinor>";
	ss << "</ec:Version>";
	ss << "</ec:InitializeFrameworkResponse>";
	WritePAOS_Response(oss, ss, strMessageID);
}

void WriteOutputAPDU(std::stringstream &oss, const std::string &strMessageID, const APDUList_t &APDUList)
{
	std::stringstream ss(std::stringstream::out);
    
	for (APDUList_t::const_iterator it = APDUList.begin(); it != APDUList.end(); ++it) {
		std::string strAPDU = *it;
		ss << "<iso:OutputAPDU>" << strAPDU.c_str() << "</iso:OutputAPDU>";
	}
    
	WriteTransmitResponse(oss, ss, strMessageID);
}

// send a HTTP POST request
std::string request_post(EIDCLIENT_CONNECTION_HANDLE hConnection, const std::string &in)
{
	std::string  strContent = "";
    
	char buf[10000];
	memset(buf, 0x00, sizeof buf);
	size_t buf_len = sizeof buf;
	EID_CLIENT_CONNECTION_ERROR err;
    
	err = eIDClientConnectionTransceivePAOS(hConnection, in.c_str(), in.size(), buf, &buf_len);
	if(err != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		eCardCore_warn(DEBUG_LEVEL_PAOS, "Error while transmit: %x", err);
		return strContent;
	}
	strContent.assign(buf, buf_len);
    
	return strContent;
}

void StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs)
{
    CParserObject* pParserObject = (CParserObject*) pUserData;
    pParserObject->m_strCurrentTag.assign(pszName);
}

void EndElementHandler(void *pUserData, const XML_Char *pszName)
{
    CParserObject* pParserObject = (CParserObject*) pUserData;
    pParserObject->m_strCurrentTag.assign("");
}

void CharacterDataHandler(void *pUserData, const XML_Char *pszData, int nLength)
{
    CParserObject* pParserObject = (CParserObject*) pUserData;
    std::string strCurrentTag = pParserObject->m_strCurrentTag;

	if (strCurrentTag.find("CertificateDescription") != std::string::npos) {
		pParserObject->m_strCertificateDescription = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "CertificateDescription : %s", pParserObject->m_strCertificateDescription.c_str());
        
	} else if (strCurrentTag.find("TransactionInfo") != std::string::npos) {
		pParserObject->m_strTransactionInfo = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "RequiredCHAT : %s", pParserObject->m_strRequiredChat.c_str());
        
	} else if (strCurrentTag.find("RequiredCHAT") != std::string::npos) {
		pParserObject->m_strRequiredChat = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "RequiredCHAT : %s", pParserObject->m_strRequiredChat.c_str());
        
	} else if (strCurrentTag.find("AuthenticatedAuxiliaryData") != std::string::npos) {
		pParserObject->m_strAuxiliaryData = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "AuthenticatedAuxiliaryData : %s", pParserObject->m_strAuxiliaryData.c_str());
        
	} else if (strCurrentTag.find("EphemeralPublicKey") != std::string::npos) {
		pParserObject->m_strEphemeralPublicKey = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "EphemeralPublicKey : %s", pParserObject->m_strEphemeralPublicKey.c_str());
        
	} else if (strCurrentTag.find("Certificate") != std::string::npos) {
		std::string  strCert = std::string(pszData, nLength);
		pParserObject->m_certificateList.push_back(strCert);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "Certificate : %s", strCert.c_str());
        
	} else if (strCurrentTag.find("Signature") != std::string::npos) {
		pParserObject->m_strSignature = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "Signature : %s", pParserObject->m_strSignature.c_str());
        
	} else if (strCurrentTag.find("InputAPDU") != std::string::npos && strCurrentTag.find("InputAPDUInfo") == std::string::npos) {
		std::string  strAPDU = std::string(pszData, nLength);
		pParserObject->m_APDUList.push_back(strAPDU);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "InputAPDU : %s", strAPDU.c_str());
        
	} else if (strCurrentTag.find("MessageID") != std::string::npos) {
		pParserObject->m_strMessageID = std::string(pszData, nLength);
//		eCardCore_debug(DEBUG_LEVEL_PAOS, "MessageID : %s", pParserObject->m_strMessageID.c_str());
	}
}

bool doParse(const CParserObject* pCParserObject, const std::string &strXML)
{
    XML_Status  xmlStatus = XML_STATUS_SUSPENDED;
    
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) pCParserObject);
    XML_SetElementHandler(parser, StartElementHandler, EndElementHandler);
	XML_SetCharacterDataHandler(parser, CharacterDataHandler);
    
	xmlStatus = XML_Parse(parser, strXML.c_str(), strXML.length(), true);
	
    XML_ParserFree(parser);
    	
    if(XML_STATUS_OK == xmlStatus)
        return true;
    else
        return false;
}

//Global variable, which is also used in the next step.
CParserObject*  pCParserObject;
EID_ECARD_CLIENT_PAOS_ERROR startPAOS(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                      const char* const cSessionID)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;
    
	std::stringstream    ioss(std::stringstream::out);
    std::string          strSessionID(cSessionID);
    bool            bParseSuccess = false;
    pCParserObject = new CParserObject();
   
	WriteStartPaos(ioss, strSessionID);
	std::string xml_str = ioss.str();
	std::string ret = request_post(hConnection, xml_str);
//return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
	
    bParseSuccess = doParse(pCParserObject, ret);

    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }
    }

    //delete pCParserObject;
    
    if( true == bParseSuccess )
        return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
    else
        return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
}


EID_ECARD_CLIENT_PAOS_ERROR getEACSessionInfo(EIDCLIENT_CONNECTION_HANDLE hConnection, const char* const cSessionID, nPADataBuffer_t* const requiredCHAT, nPADataBuffer_t* const optionalCHAT, nPADataBuffer_t* const authAuxData, nPADataBuffer_t* const cert, nPADataBuffer_t* const certDescRaw, nPADataBuffer_t* const transactionInfo)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;

    bool bParseSuccess = false;
	//Server does not expect this kind of message at this point anymore.
	//std::stringstream iossFrame(std::stringstream::out);
	//WriteInitializeFrameworkResponse(iossFrame, getMessageID(hConnection));
	//std::string xml_strFrame = iossFrame.str();
	//std::string ret = request_post(hConnection, xml_strFrame);
    //CParserObject*  pCParserObject = new CParserObject();
	
    //bParseSuccess = doParse(pCParserObject, ret);
	bParseSuccess = true;
    
    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }

        if( pCParserObject->m_strRequiredChat.length() > 0 )
        {
            std::vector<unsigned char> requChat = Hex2Byte(pCParserObject->m_strRequiredChat.c_str(), pCParserObject->m_strRequiredChat.length());
            if( 0x00 != requiredCHAT )
            {
                requiredCHAT->bufferSize = requChat.size();
                requiredCHAT->pDataBuffer = (unsigned char*) malloc(requiredCHAT->bufferSize);
                memcpy(requiredCHAT->pDataBuffer, DATA(requChat) , requChat.size() );
            }
        }

        if( pCParserObject->m_strOptionalChat.length() > 0 )
        {
            std::vector<unsigned char> optChat = Hex2Byte(pCParserObject->m_strOptionalChat.c_str(), pCParserObject->m_strOptionalChat.length() );
            if( 0x00 != optionalCHAT )
            {
                optionalCHAT->bufferSize = optChat.size();
                optionalCHAT->pDataBuffer = (unsigned char*) malloc(optionalCHAT->bufferSize);
                memcpy(optionalCHAT->pDataBuffer, DATA(optChat) , optChat.size() );
            }
        }
       
        if( pCParserObject->m_strAuxiliaryData.length() > 0 )
        {
            std::vector<unsigned char> auxData = Hex2Byte(pCParserObject->m_strAuxiliaryData.c_str(), pCParserObject->m_strAuxiliaryData.length() );
            if( 0x00 != authAuxData )
            {
                authAuxData->bufferSize = auxData.size();
                authAuxData->pDataBuffer = (unsigned char*) malloc(authAuxData->bufferSize);
                memcpy(authAuxData->pDataBuffer, DATA(auxData) , auxData.size() );
            }
        }

        if( pCParserObject->m_strCertificateDescription.length() > 0 )
        {
            std::vector<unsigned char> certDesc = Hex2Byte(pCParserObject->m_strCertificateDescription.c_str(), pCParserObject->m_strCertificateDescription.length() );
            if( 0x00 != certDescRaw )
            {
                certDescRaw->bufferSize = certDesc.size();
                certDescRaw->pDataBuffer = (unsigned char*) malloc(certDescRaw->bufferSize);
                memcpy(certDescRaw->pDataBuffer, DATA(certDesc) , certDesc.size() );
            }
        }

        if( pCParserObject->m_strTransactionInfo.length() > 0 )
        {
            std::vector<unsigned char> transInfo = Hex2Byte(pCParserObject->m_strTransactionInfo.c_str(), pCParserObject->m_strTransactionInfo.length() );
            if( 0x00 != transactionInfo )
            {
                transactionInfo->bufferSize = transInfo.size();
                transactionInfo->pDataBuffer = (unsigned char*) malloc(transactionInfo->bufferSize);
                memcpy(transactionInfo->pDataBuffer, DATA(transInfo) , transInfo.size() );
            }
        }

        if (!pCParserObject->m_certificateList.empty())
        {
            std::string strCertificate = pCParserObject->m_certificateList.front();

            if( strCertificate.length() > 0 )
            {
                std::vector<unsigned char> certTmp = Hex2Byte(strCertificate.c_str(), strCertificate.length() );
                if( 0x00 != cert )
                {
                    cert->bufferSize = certTmp.size();
                    cert->pDataBuffer = (unsigned char*) malloc(cert->bufferSize);
                    memcpy(cert->pDataBuffer, DATA(certTmp) , certTmp.size() );
                }
            }
        }
    }
    
    delete pCParserObject;

    if( true == bParseSuccess )
        return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
    else
        return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
}


EID_ECARD_CLIENT_PAOS_ERROR getTerminalAuthenticationData(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                          const nPADataBuffer_t efCardAccess,
                                                          const nPADataBuffer_t selectedCHAT,
                                                          const nPADataBuffer_t cvCACHAR,
                                                          const nPADataBuffer_t idPICC,
                                                          nPADataBuffer_t** list_certificates,
                                                          unsigned long* const list_size,
                                                          nPADataBuffer_t* const Puk_IFD_DH_CA,
							  const nPADataBuffer_t challenge,
							  nPADataBuffer_t* const signature)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;

	std::string myEFCardAccess = Byte2Hex(efCardAccess.pDataBuffer, efCardAccess.bufferSize);
	std::string myIDPICC = Byte2Hex(idPICC.pDataBuffer, idPICC.bufferSize);
	std::string myChat = Byte2Hex(selectedCHAT.pDataBuffer, selectedCHAT.bufferSize);
	std::string myCAR = std::string((char*)cvCACHAR.pDataBuffer, cvCACHAR.bufferSize);
	std::string myChallenge = Byte2Hex(challenge.pDataBuffer, challenge.bufferSize);
//	std::string myCAR = Byte2Hex(cvCACHAR.pDataBuffer, cvCACHAR.bufferSize);
//	hexdump(DEBUG_LEVEL_PAOS, "IDPICC", (void *) myIDPICC.c_str(), myIDPICC.size());
//	hexdump(DEBUG_LEVEL_PAOS, "used Chat", (void *) myChat.c_str(), myChat.size());
    
    bool bParseSuccess = false;
	std::stringstream iossFrame(std::stringstream::out);
    WriteEAC1Output(iossFrame, getMessageID(hConnection), myChat, myCAR, myEFCardAccess, myIDPICC, myChallenge);
	std::string xml_strFrame = iossFrame.str();
	std::string ret = request_post(hConnection, xml_strFrame);
    CParserObject*  pCParserObject = new CParserObject();
	
    bParseSuccess = doParse(pCParserObject, ret);
    
    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }
//        std::string cert1;
    
        *list_size = pCParserObject->m_certificateList.size();
        *list_certificates = (nPADataBuffer_t*) malloc(*list_size * sizeof(nPADataBuffer_t));
        
        nPADataBuffer_t* bufTmp = *list_certificates;
        
        while (!pCParserObject->m_certificateList.empty())
        {
            std::string cert = pCParserObject->m_certificateList.front();
            pCParserObject->m_certificateList.pop_front();
            std::vector<unsigned char> myCert = Hex2Byte(cert.c_str(), cert.length());
            
            bufTmp->bufferSize = myCert.size();
            bufTmp->pDataBuffer = (unsigned char*) malloc(bufTmp->bufferSize);
            memcpy(bufTmp->pDataBuffer, DATA(myCert) , myCert.size() );
            
            bufTmp++;
        }
    
        if( pCParserObject->m_strEphemeralPublicKey.length() > 0 )
        {
            std::vector<unsigned char>  vecPuk_IFD_DH_CA = Hex2Byte(pCParserObject->m_strEphemeralPublicKey.c_str(), pCParserObject->m_strEphemeralPublicKey.length());
            
//            if (vecPuk_IFD_DH_CA.empty())
//                return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;

            if( 0x00 != Puk_IFD_DH_CA )
            {
                Puk_IFD_DH_CA->bufferSize = vecPuk_IFD_DH_CA.size();
                Puk_IFD_DH_CA->pDataBuffer = (unsigned char*) malloc(Puk_IFD_DH_CA->bufferSize);
                memcpy(Puk_IFD_DH_CA->pDataBuffer, DATA(vecPuk_IFD_DH_CA) , vecPuk_IFD_DH_CA.size() );
            }            
//            hexdump(DEBUG_LEVEL_PAOS, "ephPubKey", DATA(vecPuk_IFD_DH_CA), vecPuk_IFD_DH_CA.size());
        }
        
        if( pCParserObject->m_strSignature.length() > 0 )
        {
            std::vector<unsigned char>  vecSignature = Hex2Byte(pCParserObject->m_strSignature.c_str(), pCParserObject->m_strSignature.length());
            
            if( 0x00 != signature )
            {
                signature->bufferSize = vecSignature.size();
                signature->pDataBuffer = (unsigned char*) malloc(signature->bufferSize);
                memcpy(signature->pDataBuffer, DATA(vecSignature) , vecSignature.size() );
            }
            hexdump(DEBUG_LEVEL_PAOS, "Signature", DATA(vecSignature), vecSignature.size());
        }
        
        delete pCParserObject;
        
//        if (!(cert1.length() % 2 == 0)) return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
    
//        if (!(pCParserObject->m_strEphemeralPublicKey.size() % 4 == 0)) return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
    }
    return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
}

EID_ECARD_CLIENT_PAOS_ERROR createSignature(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                            const nPADataBuffer_t toBeSigned,
                                            nPADataBuffer_t* const signature)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;

    bool bParseSuccess = false;
    std::string strChallenge = Byte2Hex(toBeSigned.pDataBuffer, toBeSigned.bufferSize);
    
	std::stringstream iossFrame(std::stringstream::out);
	WriteEAC2OutputChallenge(iossFrame, getMessageID(hConnection), strChallenge);
	std::string xml_strFrame = iossFrame.str();
	std::string ret = request_post(hConnection, xml_strFrame);
    CParserObject*  pCParserObject = new CParserObject();
	
    bParseSuccess = doParse(pCParserObject, ret);
    
    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }

        if( pCParserObject->m_strSignature.length() > 0 )
        {
            std::vector<unsigned char>  vecSignature = Hex2Byte(pCParserObject->m_strSignature.c_str(), pCParserObject->m_strSignature.length());
            
            if( 0x00 != signature )
            {
                signature->bufferSize = vecSignature.size();
                signature->pDataBuffer = (unsigned char*) malloc(signature->bufferSize);
                memcpy(signature->pDataBuffer, DATA(vecSignature) , vecSignature.size() );
            }
//            hexdump(DEBUG_LEVEL_PAOS, "Signature", DATA(vecSignature), vecSignature.size());
        }
    }
    
    delete pCParserObject;
    
    if( true == bParseSuccess )
        return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
    else
        return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
}

EID_ECARD_CLIENT_PAOS_ERROR EAC2OutputCardSecurity(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                   const nPADataBuffer_t efCardSecurity,
                                                   const nPADataBuffer_t AuthToken,
                                                   const nPADataBuffer_t Nonce,
                                                   nPADataBuffer_t** list_apdus,
                                                   unsigned long* const list_size)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;

    bool bParseSuccess = false;
    std::string strEfCardSecurity = Byte2Hex(efCardSecurity.pDataBuffer, efCardSecurity.bufferSize);
    std::string strAuthToken = Byte2Hex(AuthToken.pDataBuffer, AuthToken.bufferSize);
    std::string strNonce = Byte2Hex(Nonce.pDataBuffer, Nonce.bufferSize);
    
	std::stringstream iossFrame(std::stringstream::out);
	WriteEAC2OutputCardSecurity(iossFrame, getMessageID(hConnection), strEfCardSecurity, strAuthToken, strNonce);
	std::string xml_strFrame = iossFrame.str();
	std::string ret = request_post(hConnection, xml_strFrame);
    CParserObject*  pCParserObject = new CParserObject();
	
    bParseSuccess = doParse(pCParserObject, ret);
    
    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }
        
        *list_size = pCParserObject->m_APDUList.size();
        *list_apdus = (nPADataBuffer_t*) malloc(*list_size * sizeof(nPADataBuffer_t));
        
        nPADataBuffer_t* bufTmp = *list_apdus;
        
        while (!pCParserObject->m_APDUList.empty())
        {
            std::string apdu = pCParserObject->m_APDUList.front();
            pCParserObject->m_APDUList.pop_front();
            std::vector<unsigned char> myAPDU = Hex2Byte(apdu.c_str(), apdu.length());
            
            bufTmp->bufferSize = myAPDU.size();
            bufTmp->pDataBuffer = (unsigned char*) malloc(bufTmp->bufferSize);
            memcpy(bufTmp->pDataBuffer, DATA(myAPDU) , myAPDU.size() );
            
            bufTmp++;
        }
    }
    
    delete pCParserObject;
    
    if( true == bParseSuccess )
        return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
    else
        return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
}

EID_ECARD_CLIENT_PAOS_ERROR readAttributes(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                           const nPADataBuffer_t* list_inApdus,
                                           const unsigned long list_inApdus_size,
                                           nPADataBuffer_t** new_list_apdus,
                                           unsigned long* const new_list_size)
{
    if( 0x00 == hConnection )
		return EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR;

    bool bParseSuccess = false;
    APDUList_t inAPDUList;
    
    const nPADataBuffer_t* listTmp = list_inApdus;
    
    for(int i = 0; i < list_inApdus_size; i++)
    {
        std::string  strAPDU = Byte2Hex(listTmp->pDataBuffer, listTmp->bufferSize);
        inAPDUList.push_back(strAPDU);
        listTmp++;
    }
    
	std::stringstream iossFrame(std::stringstream::out);
	WriteOutputAPDU(iossFrame, getMessageID(hConnection), inAPDUList);
	std::string xml_strFrame = iossFrame.str();
	std::string ret = request_post(hConnection, xml_strFrame);
    removeMessageID(hConnection);
    CParserObject*  pCParserObject = new CParserObject();
	
    bParseSuccess = doParse(pCParserObject, ret);
    
    if(true == bParseSuccess)
    {
        if( pCParserObject->m_strMessageID.length() > 0 )
        {
            setMessageID(hConnection, pCParserObject->m_strMessageID);
        }
        
        *new_list_size = pCParserObject->m_APDUList.size();
        *new_list_apdus = (nPADataBuffer_t*) malloc(*new_list_size * sizeof(nPADataBuffer_t));
        
        nPADataBuffer_t* bufTmp = *new_list_apdus;
        
        while (!pCParserObject->m_APDUList.empty())
        {
            std::string apdu = pCParserObject->m_APDUList.front();
            pCParserObject->m_APDUList.pop_front();
            std::vector<unsigned char> myAPDU = Hex2Byte(apdu.c_str(), apdu.length());
            
            bufTmp->bufferSize = myAPDU.size();
            bufTmp->pDataBuffer = (unsigned char*) malloc(bufTmp->bufferSize);
            memcpy(bufTmp->pDataBuffer, DATA(myAPDU) , myAPDU.size() );
            
            bufTmp++;
        }
    }
    
    delete pCParserObject;
    
    if( true == bParseSuccess )
        return EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS;
    else
        return EID_ECARD_CLIENT_PAOS_PARSER_ERROR;
}

