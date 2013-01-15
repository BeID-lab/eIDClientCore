/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if defined(WIN32)
#   include <windows.h>
#   include <tchar.h>
#   include <wininet.h>
#   include <wincrypt.h>
#else
# include <pthread.h>
#endif

#define READ_BUFFER 0x10000

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <vector>
#include <iomanip>
#include <string.h>
#include <sstream>
#include <algorithm>

#define XML_STATIC
#include <expat.h>

#include <eIDClientCore.h>
#include <eIDClientConnection.h>
#include "url.h"

using namespace std;

#define HEX(x) setw(2) << setfill('0') << hex << (int)(x)

static string str_replace(string rep, string wit, string in);

class CeIdObject
{
	public:
		CeIdObject();
		~CeIdObject(void);

	public:
		void GetParams(string strToParse);

	protected:
		static void StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);
		static void EndElementHandler(void *pUserData, const XML_Char *pszName);
		static void CharacterDataHandler(void *pUserData, const XML_Char *pszName, int len);
		void OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs);
		void OnEndElement(const XML_Char *pszName);
		void OnCharacterData(const XML_Char *pszName, int len);

	public:
		string  m_strAction;
		string  m_strMethod;
		string  m_strSAMLRequest;
		string  m_strSAMLResponse;
		string  m_strSigAlg;
		string  m_strSignature;
		string  m_strRelayState;

		string  m_strSessionID;
		string  m_strPSK;
		string  m_strRefreshAddress;
		string  m_strServerAddress;

protected:
	string m_strCurrentElement;
};

CeIdObject::CeIdObject()
{
	m_strAction = "";
	m_strMethod = "";
	m_strSAMLRequest = "";
	m_strSigAlg = "";
	m_strSignature = "";
	m_strRelayState = "";
	m_strSessionID = "";
	m_strPSK = "";
	m_strRefreshAddress = "";
	m_strServerAddress = "";
	m_strCurrentElement = "";
}

CeIdObject::~CeIdObject(void)
{
}

void CeIdObject::StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs)
{
	CeIdObject *pThis = (CeIdObject *) pUserData;
	pThis ->OnStartElement(pszName, papszAttrs);
}

void CeIdObject::OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs)
{
	m_strCurrentElement.assign(pszName);
	string  strParamName = "";
	string  strParamValue = "";

	//HTML Form
	if (strcmp(m_strCurrentElement.c_str(), "form") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			string  strParam(papszAttrs[i]);

			if (strcmp(strParam.c_str(), "action") == 0) {
				m_strAction.assign(papszAttrs[i + 1]);

			} else if (strcmp(strParam.c_str(), "method") == 0) {
				m_strMethod.assign(papszAttrs[i + 1]);
			}
		}
		return;
	}

	//Object Tag
	else if (strcmp(m_strCurrentElement.c_str(), "param") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			string  strParam(papszAttrs[i]);

			if (strcmp(strParam.c_str(), "name") == 0) {
				strParamName.assign(papszAttrs[i + 1]);

			} else if (strcmp(strParam.c_str(), "value") == 0) {
				if (strcmp(strParamName.c_str(), "SessionIdentifier") == 0) {
					m_strSessionID.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "PathSecurity-Parameters") == 0) {
					m_strPSK.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "RefreshAddress") == 0) {
					m_strRefreshAddress.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "ServerAddress") == 0) {
					m_strServerAddress.assign(papszAttrs[i + 1]);
				}
			}
		}
		return;
	}

	//TCToken	
	else if (strcmp(m_strCurrentElement.c_str(), "ServerAddress") == 0) {
		//m_strServerAddress.assign(papszAttrs[0]);
	}

	//SP XML
	else if (strcmp(m_strCurrentElement.c_str(), "input") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			string  strParam(papszAttrs[i]);

			if (strcmp(strParam.c_str(), "type") == 0) {
				//              strParamName.assign(papszAttrs[i+1]);
			} else if (strcmp(strParam.c_str(), "name") == 0) {
				strParamName.assign(papszAttrs[i + 1]);

			} else if (strcmp(strParam.c_str(), "value") == 0) {
				if (strcmp(strParamName.c_str(), "SAMLRequest") == 0) {
					m_strSAMLRequest.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "SigAlg") == 0) {
					m_strSigAlg.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "Signature") == 0) {
					m_strSignature.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "RelayState") == 0) {
					m_strRelayState.assign(papszAttrs[i + 1]);

				} else if (strcmp(strParamName.c_str(), "SAMLResponse") == 0) {
					m_strSAMLResponse.assign(papszAttrs[i + 1]);
				}
			}
		}
	}
}

void CeIdObject::EndElementHandler(void *pUserData, const XML_Char *pszName)
{
	CeIdObject *pThis = (CeIdObject *) pUserData;
	pThis ->OnEndElement(pszName);
}

void CeIdObject::OnEndElement(const XML_Char *pszName)
{
	m_strCurrentElement.assign("");
}

void CeIdObject::CharacterDataHandler(void *pUserData, const XML_Char *pszName, int len)
{
	CeIdObject *pThis = (CeIdObject *) pUserData;
	pThis ->OnCharacterData(pszName, len);
}

void CeIdObject::OnCharacterData(const XML_Char *pszName, int len) {
	if(len == 1) //I often get Character Data of this length
		return;

	else if(!m_strCurrentElement.compare("ServerAddress"))
		m_strServerAddress = string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("SessionIdentifier"))
		m_strSessionID = string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("RefreshAddress"))
		m_strRefreshAddress = string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("PSK"))
		m_strPSK = string(pszName, pszName+len);

	return;

}

void CeIdObject::GetParams(string strToParse)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) this);
	XML_SetStartElementHandler(parser, StartElementHandler);
	XML_SetEndElementHandler(parser, EndElementHandler);
	XML_SetCharacterDataHandler(parser, CharacterDataHandler);
	XML_Parse(parser, strToParse.c_str(), strToParse.length(), true);
	XML_ParserFree(parser);
}

string strRefresh = "";

#ifdef _WIN32
DWORD WINAPI
#else
void *
#endif
getSamlResponseThread(void *lpParam)
{
	URL urlIDP(strRefresh.c_str());
	string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;
	connection_status = eIDClientConnectionStart(&connection, urlIDP._hostname.c_str(),
						urlIDP._port.c_str(), 0, NULL);

	if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		/* Send a GET request */
		string get("GET ");
		get += urlIDP._path;
		get += " HTTP/1.1\r\n";
		get += "Host: ";
		get += urlIDP._hostname;
		get += ":";
		get += urlIDP._port;
		get += "\r\n\r\n";
		connection_status = eIDClientConnectionSendRequest(connection,
							get.c_str(), get.size(), sz, &sz_len);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += string(sz, sz_len);
			std::string strTmp = strResult;
			std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
			size_t found = strTmp.find("<html");

			if (found != string::npos) {
				strResult = strResult.substr(found);
			} else
				std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		} else {
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		}

	} else {
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}
	connection_status = eIDClientConnectionEnd(connection);


	CeIdObject      eIdObject;
	eIdObject.GetParams(strResult);
	string SAMLResponse = eIdObject.m_strSAMLResponse.c_str();
	cout << "RelayState\t" << eIdObject.m_strRelayState.c_str() << endl;
	cout << "SAMLResponse\t" << SAMLResponse << endl;
	urlIDP = URL(eIdObject.m_strAction.c_str());
	if (!urlIDP._valid)
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	SAMLResponse = str_replace("=", "%3D", SAMLResponse);
	SAMLResponse = str_replace("+", "%2B", SAMLResponse);
	SAMLResponse = str_replace("/", "%2F", SAMLResponse);

	string strContentType = "Content-Type: application/x-www-form-urlencoded";
	string strData = "RelayState=";
	strData += eIdObject.m_strRelayState;
	strData += "&SAMLResponse=";
	strData += SAMLResponse;

	std::stringstream out;
	out << strData.length();
	string strContentLength = "Content-Length: " + out.str();
	strResult = "";
	connection = 0x00;
	string port_hack = /* FIXME urlIDP._port.c_str() */ "8080";
	connection_status = eIDClientConnectionStart(&connection, urlIDP._hostname.c_str(), port_hack.c_str(), NULL, NULL);

	if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		string request;
		std::transform(eIdObject.m_strMethod.begin(), eIdObject.m_strMethod.end(), eIdObject.m_strMethod.begin(), static_cast<int ( *)(int)>(tolower));

		if (0x00 == eIdObject.m_strMethod.compare("post")) {
			/* Send a POST request */
			request += "POST ";

		} else {
			/* Send a GET request */
			request += "GET ";
		}

		request += urlIDP._path + " HTTP/1.1\r\n";
		request += "Host: " + urlIDP._hostname + ":" + port_hack + "\r\n";
		//request += "Referer: " + strRefresh + "\r\n";
		request += strContentType + "\r\n";
		request += strContentLength + "\r\n\r\n";
		request += strData;
		memset(sz, 0x00, READ_BUFFER);
		sz_len = sizeof sz;
		connection_status = eIDClientConnectionSendRequest(connection, request.c_str(), request.size(), sz, &sz_len);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += string(sz, sz_len);
			std::string strTmp = strResult;
			std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
			size_t found = strTmp.find("<html");

			if (found != string::npos) {
				strResult = strResult.substr(found);
			} else
				std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		} else {
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		}

		eIDClientConnectionEnd(connection);

	} else {
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	cout << "Service Provider Login Page:" << std::endl;
	cout << strResult << std::endl;

	return 0;
}

#ifdef _WIN32
HANDLE  hThread;
DWORD   dwThreadId;
#else
/* TODO thread cleanup */
pthread_t hThread;

#endif
void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
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

#ifdef _WIN32
			hThread = CreateThread(
						  NULL,                   // default security attributes
						  0,                      // use default stack size
						  getSamlResponseThread,       // thread function name
						  NULL,          // argument to thread function
						  0,                      // use default creation flags
						  &dwThreadId);   // returns the thread identifier
#else
			if (pthread_create(&hThread, NULL, getSamlResponseThread, NULL))
				std::cout << "Could not create getSamlResponseThread" << std::endl;

#endif
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

	if (hThread && (error != NPACLIENT_ERROR_SUCCESS)) {
#ifdef _WIN32
		if(!TerminateThread(hThread, -1))
			std::cout << "Could not cancel SamlResponseThread: "<< GetLastError() << std::endl;
#else
		if (pthread_cancel(hThread))
			std::cout << "Could not cancel SamlResponseThread" << std::endl;
		hThread = 0;
#endif
	}

	if (hThread && (error != NPACLIENT_ERROR_SUCCESS || state == NPACLIENT_STATE_READ_ATTRIBUTES)) {
#ifdef _WIN32
		WaitForSingleObject(hThread, INFINITE); //Phew.. I hope we dont get a deadlock here?
#else
		if (pthread_join(hThread, NULL))
			std::cout << "Could not clean up SamlResponseThread" << std::endl;
		hThread = 0;
#endif
	}
}

static const char default_pin[] = "123456";
static const char *pin = default_pin;

NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input)
{
	static nPADataBuffer_t p;
	p.pDataBuffer = (unsigned char *) pin;
	p.bufferSize = strlen(default_pin);

	std::cout << "serviceName: ";
	std::cout.write((char *) description->name->pDataBuffer, description->name->bufferSize);
	std::cout << std::endl;
	std::cout << "serviceURL:  ";
	std::cout.write((char *) description->url->pDataBuffer, description->url->bufferSize);
	std::cout << std::endl;
	std::cout << "certificateDescription:" << std::endl;
	std::cout.write((char *) description->description->pDataBuffer, description->description->bufferSize);
	std::cout << std::endl;

	switch (description->chat_required->type) {
		case TT_IS:
			std::cout << "Inspection System:" << std::endl;
			if (description->chat_required->authorization.is.read_finger 	) std::cout << "\tRead Fingerprint" << std::endl;
			if (description->chat_required->authorization.is.read_iris  	) std::cout << "\tRead Iris" << std::endl;
			if (description->chat_required->authorization.is.read_eid		) std::cout << "\tRead eID" << std::endl;
			break;

		case TT_AT:
			std::cout << "Authentication Terminal:" << std::endl;
			if (description->chat_required->authorization.at.age_verification 				) std::cout << "\tVerify Age" << std::endl;
			if (description->chat_required->authorization.at.community_id_verification 		) std::cout << "\tVerify Community ID" << std::endl;
			if (description->chat_required->authorization.at.restricted_id 					) std::cout << "\tRestricted ID" << std::endl;
			if (description->chat_required->authorization.at.privileged 					) std::cout << "\tPrivileged Terminal" << std::endl;
			if (description->chat_required->authorization.at.can_allowed 					) std::cout << "\tCAN allowed" << std::endl;
			if (description->chat_required->authorization.at.pin_management 				) std::cout << "\tPIN Management" << std::endl;
			if (description->chat_required->authorization.at.install_cert 					) std::cout << "\tInstall Certificate" << std::endl;
			if (description->chat_required->authorization.at.install_qualified_cert 		) std::cout << "\tInstall Qualified Certificate" << std::endl;
			if (description->chat_required->authorization.at.read_dg1         				) std::cout << "\tRead Document Type" << std::endl;
			if (description->chat_required->authorization.at.read_dg2                  		) std::cout << "\tRead Issuing State" << std::endl;
			if (description->chat_required->authorization.at.read_dg3      					) std::cout << "\tRead Date of Expiry" << std::endl;
			if (description->chat_required->authorization.at.read_dg4 						) std::cout << "\tRead Given Names" << std::endl;
			if (description->chat_required->authorization.at.read_dg5 						) std::cout << "\tRead Family Names" << std::endl;
			if (description->chat_required->authorization.at.read_dg6 						) std::cout << "\tRead Religious/Artistic Name" << std::endl;
			if (description->chat_required->authorization.at.read_dg7 						) std::cout << "\tRead Academic Title" << std::endl;
			if (description->chat_required->authorization.at.read_dg8 						) std::cout << "\tRead Date of Birth" << std::endl;
			if (description->chat_required->authorization.at.read_dg9        				) std::cout << "\tRead Place of Birth" << std::endl;
			if (description->chat_required->authorization.at.read_dg10                		) std::cout << "\tRead Nationality" << std::endl;
			if (description->chat_required->authorization.at.read_dg11     					) std::cout << "\tRead Sex" << std::endl;
			if (description->chat_required->authorization.at.read_dg12						) std::cout << "\tRead OptionalDataR" << std::endl;
			if (description->chat_required->authorization.at.read_dg13						) std::cout << "\tRead DG 13" << std::endl;
			if (description->chat_required->authorization.at.read_dg14						) std::cout << "\tRead DG 14" << std::endl;
			if (description->chat_required->authorization.at.read_dg15						) std::cout << "\tRead DG 15" << std::endl;
			if (description->chat_required->authorization.at.read_dg16						) std::cout << "\tRead DG 16" << std::endl;
			if (description->chat_required->authorization.at.read_dg17        				) std::cout << "\tRead Normal Place of Residence" << std::endl;
			if (description->chat_required->authorization.at.read_dg18             			) std::cout << "\tRead Community ID" << std::endl;
			if (description->chat_required->authorization.at.read_dg19     					) std::cout << "\tRead Residence Permit I" << std::endl;
			if (description->chat_required->authorization.at.read_dg20						) std::cout << "\tRead Residence Permit II" << std::endl;
			if (description->chat_required->authorization.at.read_dg21						) std::cout << "\tRead OptionalDataRW" << std::endl;
			if (description->chat_required->authorization.at.write_dg21						) std::cout << "\tWrite OptionalDataRW" << std::endl;
			if (description->chat_required->authorization.at.write_dg20        				) std::cout << "\tWrite Residence Permit I" << std::endl;
			if (description->chat_required->authorization.at.write_dg19                		) std::cout << "\tWrite Residence Permit II" << std::endl;
			if (description->chat_required->authorization.at.write_dg18    					) std::cout << "\tWrite Community ID" << std::endl;
			if (description->chat_required->authorization.at.write_dg17						) std::cout << "\tWrite Normal Place of Residence" << std::endl;
			break;

		case TT_ST:
			std::cout << "Signature Terminal:" << std::endl;
			if (description->chat_required->authorization.st.generate_signature 			) cout << "\tGenerate electronic signature" << std::endl;
			if (description->chat_required->authorization.st.generate_qualified_signature 	) cout << "\tGenerate qualified electronic signature" << std::endl;
			break;

		default:
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	input->chat_selected = description->chat_required;

	if (input->pin_required)
		input->pin = &p;

	return NPACLIENT_ERROR_SUCCESS;
}

string str_replace(string rep, string wit, string in)
{
	int pos;

	while (true) {
		pos = in.find(rep);

		if (pos == -1) {
			break;

		} else {
			in.erase(pos, rep.length());
			in.insert(pos, wit);
		}
	}

	return in;
}

int getAuthenticationParams(const char *const SP_URL,
							string &strIdpAddress,
							string &strSessionIdentifier,
							string &strPathSecurityParameters)
{
	string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	URL urlSP(SP_URL);
	if (!urlSP._valid)
		return 0;

	connection_status = eIDClientConnectionStart(&connection, urlSP._hostname.c_str(), urlSP._port.c_str(), NULL, NULL);

	if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		/* Send a GET request */
		string get("GET ");
		get += urlSP._path.c_str();
		get += " HTTP/1.1\r\n";
		get += "Host: ";
		get += urlSP._hostname.c_str();
		get += ":";
		get += urlSP._port.c_str();
		get += "\r\n\r\n";
		memset(sz, 0x00, READ_BUFFER);
		connection_status = eIDClientConnectionSendRequest(connection, get.c_str(), get.size(), sz, &sz_len);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += string(sz, sz_len);
			std::string strTmp = strResult;
			std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
			size_t found = strTmp.find("<html");

			if (found != std::string::npos) {
				strResult = strResult.substr(found);

			} else {
				std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
			}

		} else {
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		}

		eIDClientConnectionEnd(connection);

	} else {
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	CeIdObject      eIdObject;
	eIdObject.GetParams(strResult);
	cout << "Action\t\t" << eIdObject.m_strAction.c_str() << endl;
	cout << "Method\t\t" << eIdObject.m_strMethod.c_str() << endl;
	cout << "SAMLRequest\t" << eIdObject.m_strSAMLRequest.c_str() << endl;
	cout << "SigAlg\t" << eIdObject.m_strSigAlg.c_str() << endl;
	cout << "Signature\t" << eIdObject.m_strSignature.c_str() << endl;
	cout << "RelayState\t" << eIdObject.m_strRelayState.c_str() << endl;
	URL urlIDP(eIdObject.m_strAction.c_str());
	if (!urlIDP._valid)
		return 0;

	string strContentType = "Content-Type: application/x-www-form-urlencoded";
	string strData = "SAMLRequest=";
	strData += eIdObject.m_strSAMLRequest;
	strData += "&SigAlg=";
	strData += eIdObject.m_strSigAlg;
	strData += "&Signature=";
	strData += eIdObject.m_strSignature;

	if (eIdObject.m_strRelayState.size() > 1) {
		strData += "&RelayState=";
		strData += eIdObject.m_strRelayState;
	}

	std::stringstream out;
	out << strData.length();
	string strContentLength = "Content-Length: " + out.str();
	strResult = "";
	connection = 0x00;
	connection_status = eIDClientConnectionStart(&connection, urlIDP._hostname.c_str(), urlIDP._port.c_str(), NULL, NULL);

	if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		string request;
		std::transform(eIdObject.m_strMethod.begin(), eIdObject.m_strMethod.end(), eIdObject.m_strMethod.begin(), static_cast<int ( *)(int)>(tolower));

		if (0x00 == eIdObject.m_strMethod.compare("post")) {
			/* Send a POST request */
			request += "POST ";

		} else {
			/* Send a GET request */
			request += "GET ";
		}

		request += urlIDP._path + " HTTP/1.1\r\n";
		request += "Host: " + urlIDP._hostname + ":" + urlIDP._port + "\r\n";
		request += strContentType + "\r\n";
		request += strContentLength + "\r\n\r\n";
		request += strData;
		memset(sz, 0x00, READ_BUFFER);
		sz_len = sizeof sz;
		connection_status = eIDClientConnectionSendRequest(connection, request.c_str(), request.size(), sz, &sz_len);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += string(sz, sz_len);
			std::string strTmp = strResult;
			std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
			size_t found = strTmp.find("<html");

			if (found != std::string::npos) {
				strResult = strResult.substr(found);
			} else {
				std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
			}

		} else {
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		}

		eIDClientConnectionEnd(connection);

	} else {
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	string response2 = strResult;
	response2 = str_replace("<PSK>", "", response2);
	response2 = str_replace("</PSK>", "", response2);
	response2 = str_replace("&uuml;", "ü", response2);
	response2 = str_replace("&ouml;", "ö", response2);
	eIdObject.GetParams(response2);
	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strPathSecurityParameters = eIdObject.m_strPSK;
	strRefresh = eIdObject.m_strRefreshAddress;
	cout << "IdpAddress\t" + strIdpAddress << std::endl;
	cout << "SessionID\t" + strSessionIdentifier << std::endl;
	cout << "PSK\t\t" + strPathSecurityParameters << std::endl;
	cout << "RefreshAddress\t" + strRefresh << std::endl;
	return 0;
}

int main(int argc, char **argv)
{
	int loopCount = 10;
	int retValue = 0;
	int serverErrorCounter = 0;
	char buffer[500];
	std::vector<double> diffv;

	const char default_serviceURL[] = "https://eidservices.bundesdruckerei.de"
		":443"
		"/ExampleSP/saml/Login?demo=Authentication+Request+Show-PKI";
	const char *serviceURL = default_serviceURL;

	switch (argc) {
		case 3:
			pin = argv[2];

		case 2:
			serviceURL = argv[1];

		case 1:

			cout << "Connection Parameters:" << std::endl;
			cout << "SP URL\t\t" << serviceURL << std::endl;
			cout << "eID PIN\t\t" << pin << std::endl;
			break;

		default:
			cout << "Usage: " << argv[0] << "[\"Service Provider URL\" [\"eID PIN\"]]" << std::endl;
			return 1;
	}

	while (0 == retValue) {
		time_t start;
		time(&start);
		string strIdpAddress("");
		string strSessionIdentifier("");
		string strPathSecurityParameters("");
		string strRef("");
        getAuthenticationParams(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
		retValue = nPAeIdPerformAuthenticationProtocolPcSc(strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
		diffv.push_back(difftime(time(0x00), start));
		sprintf(buffer, " - Read Count: %u - Server Errors: %d\n", (unsigned int) diffv.size(), serverErrorCounter);
		std::cout << "########## Error Code: " << HEX(retValue) << buffer << std::endl;

		if (diffv.size() == loopCount)
			break;
	}

	vector<double>::iterator it;
	double diffSum = 0;

	for (it = diffv.begin(); it != diffv.end(); ++it) {
		diffSum += *it;
	}

	std::cout << "Durchschnittliche Dauer bei " << diffv.size() << " Durchlaeufen: " << diffSum / diffv.size() << " Sekunden" << std::endl;
	sprintf(buffer, "########## Error Code: %X - Read Count: %u - Server Errors: %d\n", retValue, (unsigned int) diffv.size(), serverErrorCounter);
	std::cout << buffer << std::endl;
	return retValue;
}
