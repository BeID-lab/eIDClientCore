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

#define READ_BUFFER 8192

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

class CeIdObject
{
	public:
		CeIdObject();
		~CeIdObject(void);

	public:
		void OnPostCreate();
		void OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs);

		void GetParams(string strToParse);

	protected:
		static void StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);

	public:
		string  m_strAction;
		string  m_strMethod;
		string  m_strSAMLRequest;
		string  m_strSigAlg;
		string  m_strSignature;
		string  m_strRelayState;

		string  m_strSessionID;
		string  m_strPSK;
		string  m_strRefreshAddress;
		string  m_strServerAddress;
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
	string  strCurrentTag(pszName);
	string  strParamName = "";
	string  strParamValue = "";

	if (strcmp(strCurrentTag.c_str(), "param") == 0) {
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
	}

	if (strcmp(strCurrentTag.c_str(), "form") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			string  strParam(papszAttrs[i]);

			if (strcmp(strParam.c_str(), "action") == 0) {
				m_strAction.assign(papszAttrs[i + 1]);

			} else if (strcmp(strParam.c_str(), "method") == 0) {
				m_strMethod.assign(papszAttrs[i + 1]);
			}
		}
	}

	if (strcmp(strCurrentTag.c_str(), "input") == 0) {
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
				}
			}
		}
	}

	return;
}

void CeIdObject::GetParams(string strToParse)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) this);
	XML_SetStartElementHandler(parser, StartElementHandler);
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
							get.c_str(), get.size(), sz, sizeof sz);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += sz;
			size_t found = strResult.find("<html");
			if (found != string::npos)
				strResult.substr(found);
		} else {
			std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
		}

	} else {
		std::cout << __FILE__ << __LINE__ << ": Error" << std::endl;
	}

	connection_status = eIDClientConnectionEnd(connection);
	cout << strResult << endl;
	return 0;
}

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
			HANDLE  hThread;
			DWORD   dwThreadId;
			hThread = CreateThread(
						  NULL,                   // default security attributes
						  0,                      // use default stack size
						  getSamlResponseThread,       // thread function name
						  NULL,          // argument to thread function
						  0,                      // use default creation flags
						  &dwThreadId);   // returns the thread identifier
#else
			/* TODO thread cleanup */
			pthread_t hThread;

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
}

static string p("123456");
static nPADataBuffer_t pin = {(unsigned char *) p.data(), p.length()};
NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input)
{
	std::cout << "serviceName: ";
	std::cout.write((char *) description->name->pDataBuffer, description->name->bufferSize);
	std::cout << std::endl;
	std::cout << "serviceURL:  ";
	std::cout.write((char *) description->url->pDataBuffer, description->url->bufferSize);
	std::cout << std::endl;
	std::cout << "certificateDescription:" << std::endl;
	std::cout.write((char *) description->description->pDataBuffer, description->description->bufferSize);
	std::cout << std::endl;
	input->chat_selected = description->chat_required;

	if (input->pin_required)
		input->pin = &pin;

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

int getAuthenticationParams(const char *const cServerName,
							const char *const pPort,
							const char *const cPath,
							string &strIdpAddress,
							string &strSessionIdentifier,
							string &strPathSecurityParameters)
{
	string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	connection_status = eIDClientConnectionStart(&connection, cServerName, pPort, 0, NULL);

	if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		/* Send a GET request */
		string get("GET ");
		get += cPath;
		get += " HTTP/1.1\r\n";
		get += "Host: ";
		get += cServerName;
		get += ":";
		get += pPort;
		get += "\r\n\r\n";
		memset(sz, 0x00, READ_BUFFER);
		connection_status = eIDClientConnectionSendRequest(connection, get.c_str(), get.size(), sz, sizeof sz);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += sz;
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
	connection_status = eIDClientConnectionStart(&connection, urlIDP._hostname.c_str(), urlIDP._port.c_str(), 0, NULL);

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
		connection_status = eIDClientConnectionSendRequest(connection, request.c_str(), request.size(), sz, sizeof sz);

		if (connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			strResult += sz;
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
	int loopCount = 1;
	int retValue = 0;
	int serverErrorCounter = 0;
	char buffer[500];
	std::vector<double> diffv;

	while (0 == retValue) {
		time_t start;
		time(&start);
		string strIdpAddress("");
		string strSessionIdentifier("");
		string strPathSecurityParameters("");
		string strRef("");
        getAuthenticationParams("eidservices.bundesdruckerei.de", "443", "/ExampleSP/saml/Login?demo=Authentication+Request+Show-PKI", strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
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

