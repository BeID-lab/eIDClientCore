/*
* Copyright (C) 2012 Bundesdruckerei GmbH
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(WIN32)
#   include <windows.h>
#   include <tchar.h>
#   include <wininet.h>
#   include <wincrypt.h>
#endif

#define READ_BUFFER 0x20000

#include <algorithm>
#include <cstring>
#include <sstream>

#include <ctype.h>

#define XML_STATIC
#include <expat.h>

#include <eIDClientCore.h>
#include <eIDClientConnection.h>
#include <eCardCore/eCardStatus.h>

#include <debug.h>
#include <testing.h>

#ifndef DISABLE_EIDGUI
#include "eIDmfcUI.h"
#else
#include "eidui_cli.h"
#endif

#include "Test_nPAClientLib.h"

#define HEX(x) std::setw(2) << std::setfill('0') << std::hex << (int)(x)

enum enum_testcase SAML_VERSION;
const char *pin;

static std::string str_replace(std::string rep, std::string wit, std::string in);
static void urlEncode(std::string & toEncode);
static EID_CLIENT_CONNECTION_ERROR dealWithForms(std::string *submits, int numberOfSubmits, std::string startUrl, std::string baseUrl, std::string *result);

class CeIdObject
{
public:
	CeIdObject();
	~CeIdObject(void);

public:
	void GetParams(std::string strToParse);

protected:
	static void StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);
	static void EndElementHandler(void *pUserData, const XML_Char *pszName);
	static void CharacterDataHandler(void *pUserData, const XML_Char *pszName, int len);
	void OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs);
	void OnEndElement(const XML_Char *pszName);
	void OnCharacterData(const XML_Char *pszName, int len);
	std::string FindValue(std::string name, const XML_Char **papszAttrs);
	void AddData(std::string name, std::string value);

public:
	std::string  m_strAction;
	std::string  m_strMethod;
	std::string  m_strSAMLRequest;
	std::string  m_strSAMLResponse;
	std::string  m_strSigAlg;
	std::string  m_strSignature;
	std::string  m_strRelayState;

	std::string  m_strSessionID;
	std::string  m_strPSK;
	std::string  m_strRefreshAddress;
	std::string  m_strServerAddress;

	std::string m_data;
	std::string m_submit;

protected:
	std::string m_strCurrentElement;
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
	m_data = "";
}

CeIdObject::~CeIdObject(void)
{
}

std::string CeIdObject::FindValue(std::string name, const XML_Char **papszAttrs)
{
	std::string returnValue = "";
	for (int i = 0; papszAttrs[i]; i += 2) {
		std::string strParam(papszAttrs[i]);
		if (strcmp(name.c_str(), strParam.c_str()) == 0) {
			returnValue.assign(papszAttrs[i + 1]);
		}
	}

	return returnValue;
}

void CeIdObject::AddData(std::string name, std::string value)
{
	urlEncode(name);
	urlEncode(value);
	if(m_data.find(name + "=" + value) == std::string::npos){
		if(strcmp("", m_data.c_str()) != 0){
			m_data = m_data.append("&");
		}
		m_data = m_data.append(name);
		m_data = m_data.append("=");
		m_data = m_data.append(value);
	}
}

void CeIdObject::StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs)
{
	CeIdObject *pThis = (CeIdObject *) pUserData;
	pThis ->OnStartElement(pszName, papszAttrs);
}

void CeIdObject::OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs)
{
	m_strCurrentElement.assign(pszName);
	std::string  strParamName = "";
	std::string  strParamValue = "";

	//HTML Form
	if (strcmp(m_strCurrentElement.c_str(), "form") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			std::string  strParam(papszAttrs[i]);

			if (strcmp(strParam.c_str(), "action") == 0) {
				m_strAction.assign(papszAttrs[i + 1]);

			} else if (strcmp(strParam.c_str(), "method") == 0) {
				m_strMethod.assign(papszAttrs[i + 1]);
			}
		}
		return;
	}

	if(SAML_VERSION == testcase_arg_Selbstauskunft_Wuerzburg){
		//Input
		if (strcmp(m_strCurrentElement.c_str(), "input") == 0) {
			std::string type = "";
			for (int i = 0; papszAttrs[i]; i += 2) {
				std::string  strParam(papszAttrs[i]);

				type.assign(FindValue("type", papszAttrs).c_str());

				if (strcmp(type.c_str(), "hidden") == 0) {
					//Add name, value
					AddData(FindValue("name", papszAttrs), FindValue("value", papszAttrs));
				}

				if(strcmp(type.c_str(), "submit") == 0 &&
					strcmp(FindValue("value", papszAttrs).c_str(), m_submit.c_str()) == 0){
					//Add name, value
					if(strcmp(FindValue("name", papszAttrs).c_str(), "") != 0){
						AddData(FindValue("name", papszAttrs), FindValue("value", papszAttrs));
					}
				}

				if (strcmp(type.c_str(), "checkbox") == 0) {
					//Add name, value
					AddData(FindValue("name", papszAttrs), "on");
				}

			}
			return;
		}
	}
	
	//Object Tag
	else if (strcmp(m_strCurrentElement.c_str(), "param") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			std::string  strParam(papszAttrs[i]);

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

	//SP XML
	else if (strcmp(m_strCurrentElement.c_str(), "input") == 0) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			std::string  strParam(papszAttrs[i]);

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
	if(!std::string(pszName, pszName+len).compare("&") && !m_strCurrentElement.compare("RefreshAddress"))
		m_strRefreshAddress.append(std::string(pszName, pszName+len));
	if(len == 1) //I often get Character Data of this length
		return;

	else if(!m_strCurrentElement.compare("ServerAddress"))
		m_strServerAddress = std::string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("SessionIdentifier"))
		m_strSessionID = std::string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("RefreshAddress"))
		m_strRefreshAddress.append(std::string(pszName, pszName+len));

	else if(!m_strCurrentElement.compare("PSK"))
		m_strPSK = std::string(pszName, pszName+len);

	return;

}

void CeIdObject::GetParams(std::string strToParse)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) this);
	XML_SetStartElementHandler(parser, StartElementHandler);
	XML_SetEndElementHandler(parser, EndElementHandler);
	XML_SetCharacterDataHandler(parser, CharacterDataHandler);
	XML_Parse(parser, strToParse.c_str(), strToParse.length(), true);
	XML_ParserFree(parser);
}

std::string strRefresh = "";

#ifdef _WIN32
#define VCAST

DWORD WINAPI
#else
#define VCAST (void*)

void *
#endif
	getSamlResponseThread(void *lpParam)
{
	std::string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;
	connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 1;
	}

	/* Send a GET request */
	connection_status = eIDClientConnectionTransceive(connection,
		NULL, 0, sz, &sz_len);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		connection_status = eIDClientConnectionEnd(connection);
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 2;
	}

	strResult += std::string(sz, sz_len);
	std::string strTmp = strResult;
	std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
	size_t found = strTmp.find("<html");

	if (found == std::string::npos) {
		connection_status = eIDClientConnectionEnd(connection);
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 3;
	}
	strResult = strResult.substr(found);

	connection_status = eIDClientConnectionEnd(connection);
	connection = 0x00;


	CeIdObject      eIdObject;
	eIdObject.GetParams(strResult);
	std::string SAMLResponse = eIdObject.m_strSAMLResponse.c_str();
	SAMLResponse = str_replace("=", "%3D", SAMLResponse);
	SAMLResponse = str_replace("+", "%2B", SAMLResponse);
	SAMLResponse = str_replace("/", "%2F", SAMLResponse);

	std::string strData = "RelayState=";
	strData += eIdObject.m_strRelayState;
	strData += "&SAMLResponse=";
	strData += SAMLResponse;

	strResult = "";
	connection_status = eIDClientConnectionStartHttp(&connection, eIdObject.m_strAction.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 4;
	}

	memset(sz, 0x00, READ_BUFFER);
	sz_len = sizeof sz;
	connection_status = eIDClientConnectionTransceive(connection, strData.c_str(), strData.length(), sz, &sz_len);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		eIDClientConnectionEnd(connection);
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 5;
	}

	strResult += std::string(sz, sz_len);
	strTmp = strResult;
	std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));

	found = strTmp.find("<html");
	if (found == std::string::npos) {
		eIDClientConnectionEnd(connection);
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return VCAST 6;
	}

	strResult = strResult.substr(found);

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	printf("Service Provider Login Page:\n");
	puts(strResult.c_str());

	return VCAST 0;
}

int getSamlResponse2(std::string & response)
{
	std::string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;
	if(SAML_VERSION == testcase_arg_No_SAML){
		connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);
	} else if(SAML_VERSION == testcase_arg_Selbstauskunft_Wuerzburg) {
	connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, DontGetHttpHeader, FollowHttpRedirect);
	} else {
	connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
	}

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}

	connection_status = eIDClientConnectionTransceive(connection, NULL, 0 , sz, &sz_len);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}
	strResult = std::string(sz, sz_len);

	connection_status = eIDClientConnectionEnd(connection);
	connection = 0x00;

	if(SAML_VERSION == testcase_arg_No_SAML){
		response = strResult;
		return 0;
	}

	if(SAML_VERSION == testcase_arg_AutentApp || SAML_VERSION == testcase_arg_Selbstauskunft_Wuerzburg){
		response = strResult;
		return connection_status;
	} else {
		/*OL Server sends "location" with a small l... is that standard-conform?*/
		size_t posLocationBegin = strResult.find("location: ");
		if(posLocationBegin == std::string::npos)
			return -1;
		size_t posLocationEnd = strResult.find("\r\n", posLocationBegin);
		if(posLocationEnd == std::string::npos)
			return -2;

		strResult = strResult.substr(posLocationBegin + strlen("location: "), posLocationEnd - (posLocationBegin + strlen("Location: ")));

		/*You can stop here and copy strResult into your browser*/
		memset(sz, 0, READ_BUFFER);
		sz_len = READ_BUFFER;

		connection_status = eIDClientConnectionStartHttp(&connection, strResult.c_str(), NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
		if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			return connection_status;
		}

		connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);
		if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			return connection_status;
		}

		strResult = std::string(sz, sz_len);
		connection_status = eIDClientConnectionEnd(connection);
		connection = 0x00;

		posLocationBegin = strResult.find("Location: ");
		if(posLocationBegin == std::string::npos)
			return -3;
		posLocationEnd = strResult.find("\r\n", posLocationBegin);
		if(posLocationEnd == std::string::npos)
			return -4;

		strResult = strResult.substr(posLocationBegin + strlen("Location: "), posLocationEnd - (posLocationBegin + strlen("Location: ")));

		memset(sz, 0, READ_BUFFER);
		sz_len = READ_BUFFER;

		connection_status = eIDClientConnectionStartHttp(&connection, strResult.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);
		if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			return connection_status;
		}

		connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);
		if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			return connection_status;
		}

		strResult = std::string(sz, sz_len);
		connection_status = eIDClientConnectionEnd(connection);
		connection = 0x00;

		response = strResult;

		return NPACLIENT_ERROR_SUCCESS;
	}
}

#ifdef _WIN32
HANDLE  hThread;
DWORD   dwThreadId;
DWORD   g_samlResponseReturncode = 0;
#else
/* TODO thread cleanup */
pthread_t hThread;
void * g_samlResponseReturncode = 0x00;

#endif

void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	nPAeIdProtocolStateCallback_ui(state, error);

	switch (state) {
	case NPACLIENT_STATE_TA_PERFORMED:
		if(SAML_VERSION == testcase_arg_SAML_1){
#ifdef _WIN32
			hThread = CreateThread(
				NULL,                   // default security attributes
				0,                      // use default stack size
				getSamlResponseThread,       // thread function name
				NULL,          // argument to thread function
				0,                      // use default creation flags
				&dwThreadId);   // returns the thread identifier
		} else {
			if (pthread_create(&hThread, NULL, getSamlResponseThread, NULL))
				printf("Could not create getSamlResponseThread\n");
#endif
		}
		break;
	default:
		break;
	}

	if (hThread && (error != NPACLIENT_ERROR_SUCCESS)) {
#ifdef _WIN32
		if(!TerminateThread(hThread, -1))
			printf("Could not cancel SamlResponseThread: %s\n", GetLastError());
#else
#if HAVE_DECL_PTHREAD_CANCEL
		if (pthread_cancel(hThread))
			printf("Could not cancel SamlResponseThread\n");
#endif
		hThread = 0;
#endif
	}

	if (hThread && (error != NPACLIENT_ERROR_SUCCESS || state == NPACLIENT_STATE_READ_ATTRIBUTES)) {
#ifdef _WIN32
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &g_samlResponseReturncode);
		CloseHandle(hThread);
#else
		if (pthread_join(hThread, &g_samlResponseReturncode))
			printf("Could not clean up SamlResponseThread\n");
		hThread = 0;
#endif
	}
}

NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input)
{
	if (input->pin_required && pin != NULL) {
		strncpy((char *) input->pin.pDataBuffer, pin, MAX_PIN_SIZE);
		input->pin.bufferSize = strlen(pin);
	}

	return nPAeIdUserInteractionCallback_ui(description, input);
}

std::string str_replace(std::string rep, std::string wit, std::string in)
{
	int pos = 0;

	while (true) {
		pos = in.find(rep, pos);

		if (pos == -1) {
			break;

		} else {
			in.erase(pos, rep.length());
			in.insert(pos, wit);
			pos += wit.length();
		}
	}

	return in;
}

std::string str_replace_ifnot(std::string rep, std::string wit, std::string ifnot, std::string in)
{
	int pos_rep = 0;
	int pos_ifnot = 0;

	while (true) {
		pos_rep = in.find(rep, pos_rep);
		pos_ifnot = in.find(ifnot, pos_ifnot);

		if (pos_rep == -1) {
			break;

		} else {
			if(pos_rep != pos_ifnot){
				in.erase(pos_rep, rep.length());
				in.insert(pos_rep, wit);
				pos_rep += wit.length();
			}
			else {
				pos_rep++;
			}
			pos_ifnot = pos_rep;
		}
	}

	return in;
}

void urlDecode(std::string & toDecode)
{
	if(toDecode.find("%") == std::string::npos)
		return;
	toDecode = str_replace("%2B", "+", toDecode);
	toDecode = str_replace("%2F", "/", toDecode);
	toDecode = str_replace("%3A", ":", toDecode);
	toDecode = str_replace("%3D", "=", toDecode);
	toDecode = str_replace("%3F", "?", toDecode);
}

static void urlEncode(std::string & toEncode)
{
	toEncode = str_replace("+", "%2B", toEncode);
	toEncode = str_replace("/", "%2F", toEncode);
	toEncode = str_replace(":", "%3A", toEncode);
	toEncode = str_replace("=", "%3D", toEncode);
	toEncode = str_replace("?", "%3F", toEncode);
}

static EID_CLIENT_CONNECTION_ERROR dealWithForms(std::string *submits, int numberOfSubmits, std::string startUrl, std::string baseUrl, std::string *result){
	std::string  strResult = "";
	std::string url = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	std::vector<std::string> forms;
	int found_begin;
	int found_end;
	/* Usually something like "<form action=....>"
	* Other special cases are not considered */
	std::string form_begin = "<form";
	std::string form_end = "</form>";

	//For every submit
	for(int i = 0; i < numberOfSubmits + 1; i++){
		CeIdObject eIdObject;
		if(i > 0)
			eIdObject.m_submit = submits[i - 1];

		//Replace some HTML stuff, which can not be handled by libexpat
		strResult = str_replace_ifnot("&", "&amp;", "&amp;", strResult);
		/* Find all forms and save them in a string array. While there are still forms in string,
		* search after already processed part of string. At the beginning, start at 0. */
		found_begin = 0;
		found_end = 0;
		while((found_begin = strResult.find(form_begin, found_end)) != std::string::npos){
			found_end = strResult.find(form_end, found_begin + form_begin.length());
			if(found_end != std::string::npos){
				//Copy string to vector
				forms.push_back(strResult.substr(found_begin, found_end + form_end.length() - found_begin));
				//Change position to start search
				found_end += form_end.length();
			}
		}

		//Get data from forms
		while(!forms.empty()){
			eIdObject.GetParams(forms.back());
			forms.pop_back();
		}

		//Get next page
		strResult = "";

		if(i == 0)
			eIdObject.m_strAction = startUrl;

		if(eIdObject.m_strAction.find("http", 0) != 0)
			url = baseUrl + eIdObject.m_strAction;
		else
			url = eIdObject.m_strAction;

		connection_status = eIDClientConnectionStartHttp(&connection, url.c_str(), NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
		if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
			printf("%s:%d Error\n", __FILE__, __LINE__);
			return connection_status;
		}

		memset(sz, 0x00, READ_BUFFER);
		sz_len = sizeof sz;

		connection_status = eIDClientConnectionTransceive(connection, eIdObject.m_data.c_str(), eIdObject.m_data.size(), sz, &sz_len);
		if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
		{
			printf("%s:%d Error\n", __FILE__, __LINE__);
			return connection_status;
		}

		strResult += std::string(sz, sz_len);

		connection_status = eIDClientConnectionEnd(connection);
		if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
		{
			printf("%s:%d Error\n", __FILE__, __LINE__);
			return connection_status;
		}
	}

	*result = strResult;
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

int getAuthenticationParams2(const char *const SP_URL,
	std::string &strIdpAddress,
	std::string &strSessionIdentifier,
	std::string &strPathSecurityParameters)
{
	std::string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	//Send Form with selected Attributes
	connection_status = eIDClientConnectionStartHttp(&connection, SP_URL, NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	std::string data;
	data = "requestAttributes=requestDocumentType&requestAttributes=requestIssuingState&requestAttributes=requestGivenNames&requestAttributes=requestFamilyNames&requestAttributes=requestArtisticName&requestAttributes=requestAcademicTitle&requestAttributes=requestDateOfBirth&requestAttributes=requestPlaceOfBirth&requestAttributes=requestPlaceOfResidence&requestAttributes=verifyCI&refCI=0276&requestAttributes=verifyAge&refAge=18&requestAttributes=performRI";
	memset(sz, 0x00, READ_BUFFER);
	connection_status = eIDClientConnectionTransceive(connection, data.c_str(), data.size(), sz, &sz_len);

	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	strResult = std::string(sz, sz_len);

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	size_t locationBegin = strResult.find("tcTokenURL=") + strlen("tcTokenURL=");
	size_t locationEnd =  strResult.find("\r\n", locationBegin);

	if (locationBegin == std::string::npos || locationEnd == std::string::npos) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return -2; //We need ONE File for Errorcodes
	}

	strResult = strResult.substr(locationBegin, locationEnd-locationBegin);
	urlDecode(strResult);
	//strResult = str_replace("https", "http", strResult);

	//Get AuthnRequest
	connection_status = eIDClientConnectionStartHttp(&connection, strResult.c_str(), NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	memset(sz, 0x00, READ_BUFFER);
	sz_len = sizeof sz;
	connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);

	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	strResult = std::string(sz, sz_len);

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	locationBegin = strResult.find("Location: ") + strlen("Location: ");
	locationEnd =  strResult.find("\r\n", locationBegin);
	if (locationBegin == std::string::npos || locationEnd == std::string::npos) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return -2; //We need ONE File for Errorcodes
	}

	strResult = strResult.substr(locationBegin, locationEnd-locationBegin);

	//Get tcToken
	connection_status = eIDClientConnectionStartHttp(&connection, strResult.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	memset(sz, 0x00, READ_BUFFER);
	sz_len = sizeof sz;
	connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);

	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	strResult = std::string(sz, sz_len);

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	CeIdObject      eIdObject;
	eIdObject.GetParams(strResult);
	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strRefresh = eIdObject.m_strRefreshAddress;
	strPathSecurityParameters = eIdObject.m_strPSK;
	return 0;
}

int getAuthenticationParams(const char *const SP_URL,
	std::string &strIdpAddress,
	std::string &strSessionIdentifier,
	std::string &strPathSecurityParameters)
{

	std::string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	connection_status = eIDClientConnectionStartHttp(&connection, SP_URL, NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}
	memset(sz, 0x00, READ_BUFFER);
	connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);

	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		eIDClientConnectionEnd(connection);
		connection = 0x00;
		return connection_status;
	}

	strResult += std::string(sz, sz_len);
	std::string strTmp = strResult;
	std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
	size_t found = strTmp.find("<html");
	if (found == std::string::npos) {
				printf("%s:%d Error\n", __FILE__, __LINE__);
		return -1;
	}
	strResult = strResult.substr(found);

	eIDClientConnectionEnd(connection);
	connection = 0x00;


	CeIdObject      eIdObject;
	eIdObject.GetParams(strResult);
	std::string strData = "SAMLRequest=";
	//OL-Server wants url-encoded POST-Data..
	urlEncode(eIdObject.m_strSAMLRequest);
	strData += eIdObject.m_strSAMLRequest;
	if(!eIdObject.m_strSigAlg.empty()) {
		strData += "&SigAlg=";
		strData += eIdObject.m_strSigAlg;
	}
	if(!eIdObject.m_strSignature.empty()) {
		strData += "&Signature=";
		strData += eIdObject.m_strSignature;
	}

	if (eIdObject.m_strRelayState.size() > 1) {
		strData += "&RelayState=";
		strData += eIdObject.m_strRelayState;
	}

	strResult = "";
	connection_status = eIDClientConnectionStartHttp(&connection, eIdObject.m_strAction.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	memset(sz, 0x00, READ_BUFFER);
	sz_len = sizeof sz;

	connection_status = eIDClientConnectionTransceive(connection, strData.c_str(), strData.size(), sz, &sz_len);

	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	strResult += std::string(sz, sz_len);

	strTmp = strResult;
	std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
	found = strTmp.find("<html");

	if (found != std::string::npos) {
		strResult = strResult.substr(found);
	} else {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return -2;
	}

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	std::string response2 = strResult;
	response2 = str_replace("<PSK>", "", response2);
	response2 = str_replace("</PSK>", "", response2);
	response2 = str_replace("&uuml;", "ü", response2);
	response2 = str_replace("&ouml;", "ö", response2);
	eIdObject.GetParams(response2);
	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strPathSecurityParameters = eIdObject.m_strPSK;
	strRefresh = eIdObject.m_strRefreshAddress;
	//printf("IdpAddress\t" + strIdpAddress << std::endl;
	//printf("SessionID\t" + strSessionIdentifier << std::endl;
	//printf("PSK\t\t" + strPathSecurityParameters << std::endl;
	//printf("RefreshAddress\t" + strRefresh << std::endl;
	return 0;
}

int getAuthenticationParamsSelbstauskunftWuerzburg(const char *const SP_URL,
	std::string &strIdpAddress,
	std::string &strSessionIdentifier,
	std::string &strPathSecurityParameters)
{
	std::string startUrl = SP_URL;
	std::string baseUrl = "https://www.buergerserviceportal.de";
	std::string strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	//If cookie file exists, delete it, so we do not start an old session
	remove(EIDCC_COOKIE_FILE);

	std::string submits [] = {"Weiter", "Online-Ausweisfunktion"};
	connection_status = dealWithForms(submits, 2, startUrl, baseUrl, &strResult);
	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}
	
	//Parse strResult for the redirect URL
	std::string tcTokenURL = "";
	if (strResult.find("HTTP/1.1 302 Moved Temporarily") == 0){
		std::string searchString = "Location: http://127.0.0.1:24727/eID-Client?tcTokenURL=";
		int copyStart = strResult.find(searchString) + searchString.length();
		int carriageReturn = strResult.find("\r", copyStart) - copyStart;
		int newLine = strResult.find("\n", copyStart) - copyStart;
		tcTokenURL = strResult.substr(copyStart, carriageReturn <= newLine ? carriageReturn : newLine);
	}
	
	//Now download the tcToken
	connection_status = eIDClientConnectionStartHttp(&connection, tcTokenURL.c_str(), NULL, NULL, DontGetHttpHeader, FollowHttpRedirect);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}
	
	memset(sz, 0x00, READ_BUFFER);
	sz_len = sizeof sz;
	connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);
	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}
	strResult = std::string(sz, sz_len);

	//The data for starting eidcc should now be contained in strResult, we just need to get it out of there
	CeIdObject eIdObject;
	eIdObject.GetParams(strResult);

	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strPathSecurityParameters = eIdObject.m_strPSK;
	strRefresh = eIdObject.m_strRefreshAddress;
	//printf("IdpAddress\t %s\n", strIdpAddress.c_str());
	//printf("SessionID\t %s\n", strSessionIdentifier.c_str());
	//printf("PSK\t\t %s\n", strPathSecurityParameters.c_str());
	//printf("RefreshAddress\t %s\n", strRefresh.c_str());
	return 0;
}

int getAuthenticationParamsAutentApp(const char *const SP_URL,
	std::string &strIdpAddress,
	std::string &strSessionIdentifier,
	std::string &strPathSecurityParameters){

	std::string  strResult = "";
	EIDCLIENT_CONNECTION_HANDLE connection = 0x00;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[READ_BUFFER];
	size_t sz_len = sizeof sz;

	connection_status = eIDClientConnectionStartHttp(&connection, SP_URL, NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);

	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}
	memset(sz, 0x00, READ_BUFFER);
	
	connection_status = eIDClientConnectionTransceive(connection, NULL, 0, sz, &sz_len);
	
	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		eIDClientConnectionEnd(connection);
		connection = 0x00;
		return connection_status;
	}

	strResult += std::string(sz, sz_len);

	eIDClientConnectionEnd(connection);
	connection = 0x00;

	CeIdObject eIdObject;
	std::string response2 = strResult;
	//response2 = str_replace("<PSK>", "", response2);
	//response2 = str_replace("</PSK>", "", response2);
	//response2 = str_replace("&amp;", "", response2);
	eIdObject.GetParams(response2);
	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strPathSecurityParameters = eIdObject.m_strPSK;
	strRefresh = eIdObject.m_strRefreshAddress;
	//dirty
	//if(strRefresh.find("mode=") != strRefresh.find("&") + 1)
	//	strRefresh.insert(strRefresh.find("mode="), "&");
	
	//printf("IdpAddress: %s\n", strIdpAddress.c_str());
	//printf("SessionID: %s\n", strSessionIdentifier.c_str());
	//printf("PSK: %s\n", strPathSecurityParameters.c_str());
	//printf("RefreshAddress: %s\n", strRefresh.c_str());
	return 0;
}

int performEID(std::string strServiceURL,
		std::string strIdpAddress, 
		std::string strSessionIdentifier,
		std::string strPathSecurityParameters,
		std::string strRef,
		std::string cardReaderName,
		std::string &response){
	const char *serviceURL = strServiceURL.c_str();
	if(strIdpAddress == "")
		strIdpAddress = strServiceURL;
	if(strSessionIdentifier == "")
		strSessionIdentifier = static_cast<std::ostringstream*>( &(std::ostringstream() << rand()) )->str();

	int retValue = 0;
	
	switch(SAML_VERSION){
		case testcase_arg_SAML_1:
			retValue = getAuthenticationParams(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
			break;
		case testcase_arg_SAML_2:
			retValue = getAuthenticationParams2(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
			break;
		case testcase_arg_No_SAML:
			strIdpAddress = strServiceURL + "mobileECardAPI";
			strRefresh = strServiceURL + "getResult?sessionid=" + strSessionIdentifier;
			break;
		case testcase_arg_Selbstauskunft_Wuerzburg:
			retValue = getAuthenticationParamsSelbstauskunftWuerzburg(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
			break;
		case testcase_arg_AutentApp:
			retValue = getAuthenticationParamsAutentApp(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
			break;
		default:
			break;
	}

	if(retValue != 0) return retValue;

	retValue = nPAeIdPerformAuthenticationProtocol(READER_PCSC, strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), cardReaderName.c_str(), 0x00, nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
	//retValue = nPAeIdPerformAuthenticationProtocol(READER_EXTERNAL, strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), cardReaderName.c_str(), 0x00, nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
	if(retValue != NPACLIENT_ERROR_SUCCESS) return retValue;
	if(g_samlResponseReturncode != 0) return NPACLIENT_ERRO;

	if(SAML_VERSION == testcase_arg_SAML_2 || SAML_VERSION == testcase_arg_No_SAML
		|| SAML_VERSION == testcase_arg_Selbstauskunft_Wuerzburg
		|| SAML_VERSION == testcase_arg_AutentApp){
		retValue = getSamlResponse2(response);
	}
	
	return retValue;
}
