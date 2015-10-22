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
#else
# include <unistd.h>
# include <pthread.h>
#endif

#define READ_BUFFER 0x20000

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <vector>

#include <string>
#include <fstream>
#include <streambuf>

#include <getopt.h>
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

#define SAML_1 1
#define SAML_2 2
#define NO_SAML 3
#define SAML_SELBSTAUSKUNFT_WUERZBURG 4
#define SAML_AUTENTAPP 5

#if defined SAML_VERSION_SAML_1
#define SAML_VERSION SAML_1
#elif defined SAML_VERSION_SAML_2
#define SAML_VERSION SAML_2
#elif defined SAML_VERSION_NO_SAML
#define SAML_VERSION NO_SAML
#elif defined SELBSTAUSKUNFT_WUERZBURG
#define SAML_VERSION SAML_SELBSTAUSKUNFT_WUERZBURG
#elif defined AUTENTAPP
#define SAML_VERSION SAML_AUTENTAPP
#else
#define SAML_VERSION NO_SAML
#endif

const char *pin = NULL;

#define HEX(x) std::setw(2) << std::setfill('0') << std::hex << (int)(x)

static std::string str_replace(std::string rep, std::string wit, std::string in);
static void urlEncode(std::string & toEncode);
static std::string str_replace_ifnot(std::string rep, std::string wit, std::string ifnot, std::string in);
#ifdef SELBSTAUSKUNFT_WUERZBURG
static EID_CLIENT_CONNECTION_ERROR dealWithForms(std::string *submits, int numberOfSubmits, std::string startUrl, std::string baseUrl, std::string *result);
#endif

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

#ifdef SELBSTAUSKUNFT_WUERZBURG
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
#endif

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
#if SAML_VERSION == NO_SAML
	connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);
#else
	connection_status = eIDClientConnectionStartHttp(&connection, strRefresh.c_str(), NULL, NULL, GetHttpHeader, DontFollowHttpRedirect);
#endif

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

#if SAML_VERSION == NO_SAML
	response = strResult;
	return 0;
#endif

#ifdef SELBSTAUSKUNFT_WUERZBURG
	int pos = strResult.find("url=");
	std::string url = strResult.substr(pos + 4, strResult.find("\"", pos + 5) - pos - 4);
	std::string submits [1] = {"Weiter"};
	//Empty baseUrl works, because url in action (which will come from server) starts with http.
	std::string result = "";
	connection_status = dealWithForms(submits, 1, url, "", &result);
	response = result;
	return connection_status;
#elif defined AUTENTAPP
	response = strResult;
	return connection_status;
#else

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
#endif
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
#if SAML_VERSION == SAML_1
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
			printf("Could not create getSamlResponseThread\n");

#endif
#endif //SAML_VERSION_1
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

#ifdef SELBSTAUSKUNFT_WUERZBURG
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

		connection_status = eIDClientConnectionStartHttp(&connection, url.c_str(), NULL, NULL, DontGetHttpHeader, DontFollowHttpRedirect);
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
#endif

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

#ifdef SELBSTAUSKUNFT_WUERZBURG
int getAuthenticationParamsSelbstauskunftWuerzburg(const char *const SP_URL,
	std::string &strIdpAddress,
	std::string &strSessionIdentifier,
	std::string &strPathSecurityParameters)
{
	std::string startUrl = SP_URL;
	std::string baseUrl = "https://www.buergerserviceportal.de";
	std::string  strResult = "";
	EID_CLIENT_CONNECTION_ERROR connection_status;

	//If cookie file exists, delete it, so we do not start an old session
	remove(EIDCC_COOKIE_FILE);

	std::string submits [4] = {"Weiter", "Online-Ausweisfunktion", "Weiter", "Weiter"};
	connection_status = dealWithForms(submits, 4, startUrl, baseUrl, &strResult);
	if(connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS)
	{
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return connection_status;
	}

	//The data for starting eidcc should now be contained in strResult, we just need to get it out of there
	std::string strTmp = strResult;
	std::transform(strTmp.begin(), strTmp.end(), strTmp.begin(), static_cast<int ( *)(int)>(tolower));
	int found = strTmp.find("<param");

	if (found != std::string::npos) {
		strResult = strResult.substr(found);
	} else {
		printf("%s:%d Error\n", __FILE__, __LINE__);
		return -2;
	}

	CeIdObject eIdObject;
	std::string response2 = strResult;
	response2 = str_replace("<PSK>", "", response2);
	response2 = str_replace("</PSK>", "", response2);
	response2 = str_replace("&uuml;", "ü", response2);
	response2 = str_replace("&ouml;", "ö", response2);
	response2 = str_replace("</body>", "", response2);
	response2 = str_replace("</div>", "", response2);
	response2 = str_replace("<div>", "", response2);
	response2 = str_replace("</object>", "", response2);
	response2 = str_replace_ifnot("&", "&amp;", "&amp;", response2);
	response2 = "<html>" + response2;

	eIdObject.GetParams(response2);

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
#endif

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
	printf("response2: %s\n", response2.c_str());
	eIdObject.GetParams(response2);
	strIdpAddress = eIdObject.m_strServerAddress;
	strSessionIdentifier = eIdObject.m_strSessionID;
	strPathSecurityParameters = eIdObject.m_strPSK;
	strRefresh = eIdObject.m_strRefreshAddress;
	//dirty
	//if(strRefresh.find("mode=") != strRefresh.find("&") + 1)
	//	strRefresh.insert(strRefresh.find("mode="), "&");
	printf("IdpAddress: %s\n", strIdpAddress.c_str());
	printf("SessionID: %s\n", strSessionIdentifier.c_str());
	printf("PSK: %s\n", strPathSecurityParameters.c_str());
	printf("RefreshAddress: %s\n", strRefresh.c_str());
	return 0;
}

void printStatistics(int retValue, unsigned int size, int serverErrorCounter, time_t startTime){
	printf("Duration for eID dialog: %f seconds\n", difftime(time(0), startTime));
	printf("main -------------------- end of eID dialog --------------------\n");
	printf("Error Code: %X - Read Count: %u - Server Errors: %u\n", retValue, size, serverErrorCounter);
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
	
#if SAML_VERSION == SAML_1
	retValue = getAuthenticationParams(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
#elif SAML_VERSION == SAML_2
	retValue = getAuthenticationParams2(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
#elif SAML_VERSION == NO_SAML
	strIdpAddress = strServiceURL + "mobileECardAPI";
	strRefresh = strServiceURL + "getResult?sessionid=" + strSessionIdentifier;
#elif defined SELBSTAUSKUNFT_WUERZBURG
	retValue = getAuthenticationParamsSelbstauskunftWuerzburg(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
#elif defined AUTENTAPP
	retValue = getAuthenticationParamsAutentApp(serviceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);
#endif
	if(retValue != 0) return retValue;

	retValue = nPAeIdPerformAuthenticationProtocol(READER_PCSC, strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), cardReaderName.c_str(), 0x00, nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
	//retValue = nPAeIdPerformAuthenticationProtocol(READER_EXTERNAL, strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), cardReaderName.c_str(), 0x00, nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);
	if(retValue != NPACLIENT_ERROR_SUCCESS) return retValue;
	if(g_samlResponseReturncode != 0) return NPACLIENT_ERRO;

#if SAML_VERSION == SAML_2 || SAML_VERSION == NO_SAML || defined SELBSTAUSKUNFT_WUERZBURG || defined AUTENTAPP
	retValue = getSamlResponse2(response);
#endif
	return retValue;
}

#ifndef AS_LIBRARY
int main(int argc, char **argv)
{
	int loopCount = 1;
	int retValue = 0;
	int serverErrorCounter = 0;
	char buffer[500];
	std::vector<double> diffv;

#ifdef SELBSTAUSKUNFT_WUERZBURG
	const char default_serviceURL[] = "https://www.buergerserviceportal.de/bayern/wuerzburg/bspx_selbstauskunft";
#elif defined AUTENTAPP
	const char default_serviceURL[] = "https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=autentappde";
#else
	const char default_serviceURL[] = "https://eidservices.bundesdruckerei.de"
		":443"
		"/ExampleSP/saml/Login?demo=Authentication+Request+Show-PKI";
#endif
	const char *serviceURL = default_serviceURL;
	std::string cardReaderName;

	std::string usageString = "Usage: ";
	usageString.append(argv[0]);
	usageString.append(" [OPTIONS]\n"
	"\tOptions:\n"
	"\t\t-s : Service Provider URL\n"
	"\t\t-c : Part of Card Reader Name (This parameter may consist of multiple strings)\n"
	"\t\t-p : PIN\n"
	"\t\t-l : Loopcount\n"
	"\t\t-a : Cancel after PAOS connection establishment\n"
	"\t\t-v : Debug level (verbosity) as a number. Debug levels are:\n"
	"\t\t\t APDU :\t\t1\n"
	"\t\t\t CRYPTO :\t2\n"
	"\t\t\t SSL :\t\t4\n"
	"\t\t\t PAOS :\t\t8\n"
	"\t\t\t CARD :\t\t16\n"
	"\t\t\t CLIENT :\t32\n"
	"\t\t\t To choose multiple Debug Levels at the same time, just sum "
	"the corresponding numbers and take the result as parameter.\n");

	USED_DEBUG_LEVEL = 0;
	CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT = 0;
	int c;
	bool appendToCardReaderName = false;
	while ((c = getopt (argc, argv, "-s:p:l:av:c:")) != -1){
		if(c != 1){
			appendToCardReaderName = false;
		}
		switch (c){
			case 's':
				serviceURL = optarg;
				break;
			case 'p':
				pin = optarg;
				break;
			case 'l':
				loopCount = atoi(optarg);
				break;
			case 'v':
				USED_DEBUG_LEVEL = atoi(optarg);
				break;
			case 'a':
				CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT = 1;
				break;
			case 'c':
				cardReaderName.append(optarg);
				appendToCardReaderName = true;
				break;
			//Get all the strings of the Card Reader Name
			case 1:
				if(appendToCardReaderName == true){
					cardReaderName.push_back(' ');
					cardReaderName.append(optarg);
					break;
				} else {
					printf(usageString.c_str());
					printf("Unknown non-option argument: %s\n", optarg);
					return 1;
				}
			case '?':
				printf(usageString.c_str());
				if (isprint (optopt))
				  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
				  fprintf (stderr,
						   "Unknown option character `\\x%x'.\n",
						   optopt);
				return 1;
			default:
				printf(usageString.c_str());
				return 1;
		}
	}

	printf("Connection Parameters:\n");
	printf("SP URL\t\t%s\n", serviceURL);
	printf("eID PIN\t\t%s\n", pin);
	printf("Cardreader Substring\t%s\n", cardReaderName.c_str());
	printf("Loop Count\t%i\n", loopCount);
	printf("Debug Level\t%i\n", USED_DEBUG_LEVEL);

	int n = 0;
	srand(time(0));
	time_t loopStart = time(0);
	while (n < loopCount) {
		time_t startTime = time(0);
		retValue = 0;
		++n;
		std::string strServiceURL(serviceURL);
		std::string strIdpAddress(strServiceURL);
		std::string strSessionIdentifier = static_cast<std::ostringstream*>( &(std::ostringstream() << rand()) )->str();
		std::string strPathSecurityParameters("");
		std::string strRef("");
		std::string response;

		printf("main -------------------- start of %d. eID dialog --------------------\n", n);

		retValue = performEID(strServiceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters,
			strRef, cardReaderName, response);

		//retValue may also be NPACLIENT_ERROR_SUCCESS or ECARD_SUCCESS. These are both also 0.
		if(retValue != 0)
		{
			printf("%s:%d Error %08lX\n", __FILE__, __LINE__, retValue);
			serverErrorCounter++;
			printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);
			continue;
		}
#if SAML_VERSION == SAML_2 || SAML_VERSION == NO_SAML || defined SELBSTAUSKUNFT_WUERZBURG || defined AUTENTAPP
#if !defined SELBSTAUSKUNFT_WUERZBURG && !defined AUTENTAPP
		printf(response.c_str());
#endif
#endif

		if (response.find("<errorStatus>") != std::string::npos || response.find("ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error<") != std::string::npos ) {
			// In case of faulty eID dialog the Service Provider shows via
			// SAML-IF a <errorStatus> element
			// SOAP-IF a <ResultMajor> element with content "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
			printf("%s:%d Error: eID dialog with an error result detected\n", __FILE__, __LINE__);
			serverErrorCounter++;
		}

		//FIXME: We have to push_back sometime, otherwise statistic output is faulty
		diffv.push_back(difftime(time(0), startTime));

#if defined AUTENTAPP
		int found = response.find("<html");

		if (found != std::string::npos) {
			response = response.substr(found);
		} else {
			printf("%s:%d Error\n", __FILE__, __LINE__);
			printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);
			return -2;
		}
#endif

#if defined SELBSTAUSKUNFT_WUERZBURG || defined AUTENTAPP
		std::stringstream stream;
		response = str_replace_ifnot("\"", "\\\"", "\\\"", response);
		stream <<"echo \""<<response.c_str()<<"\" | lynx -stdin -xhtml-parsing";
		if(system(stream.str().c_str()))
			printf(response.c_str());
#endif

		printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);

		printf("Wait 2 seconds before next request....\n");
#if defined(WIN32)
        Sleep(2000);
#else
		usleep(2000);
// as long as a bug in libc++ prevents clang from including chrono correctly, use usleep.
// but chrono is the more portable way, as its c++11 standard
//        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
#endif

	}

	std::vector<double>::iterator it;
	double diffSum = 0;

	for (it = diffv.begin(); it != diffv.end(); ++it) {
		diffSum += *it;
	}

	printf("Overall duration for all %d eID dialogs: %f seconds\n", loopCount, (difftime(time(0), loopStart)));
	printf("Average time for %d eID dialogs: %f seconds\n",
	   	diffv.size(), (diffv.size()==0 ? 0 : diffSum/diffv.size()));
	sprintf(buffer, "########## Error Code: %X - Read Count: %u - Server Errors: %u\n", retValue, (unsigned int) diffv.size(), serverErrorCounter);
	puts(buffer);
	if (retValue != 0x00000000) std::exit(EXIT_FAILURE);
	std::exit(EXIT_SUCCESS);
}
#endif
