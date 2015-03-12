#include <stdio.h>
#include <string.h>
#include <civetweb.h>
#include <CivetServer.h>
#include <curl/curl.h>
#include "CeIdObject.h"
#include <eIDClientCore.h>
#include <eIDClientConnection.h>
#include <sstream>
#include "debug.h"
#include <eidui_cli.h>
#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#endif
using namespace std;

#if _WIN32
#define snprintf _snprintf
#define mutex_lock(X) WaitForSingleObject(X, INFINITE)
#define mutex_unlock(X) ReleaseMutex(X)
#define sleepMilliseconds(X) Sleep(X)
#define sleepInfinite() Sleep(INFINITE)
static HANDLE ghMutex;
#else
#define mutex_lock(X) pthread_mutex_lock(&X)
#define mutex_unlock(X) pthread_mutex_unlock(&X)
static pthread_mutex_t ghMutex = PTHREAD_MUTEX_INITIALIZER;
#define sleepMilliseconds(X) usleep(X * 1000)
#define sleepInfinite() pause()
typedef unsigned long DWORD;
#endif


static NPACLIENT_ERROR gError = NPACLIENT_ERROR_SUCCESS;
static CeIdObject gAuthParams;
static string gUserInteractionHtml;
static string gPin;

static int begin_request_handler(struct mg_connection *conn); 
void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error);
NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input);


static nPAeIdUserInteractionCallback_t fnUserInteractionCallback = nPAeIdUserInteractionCallback;
static nPAeIdProtocolStateCallback_t fnCurrentStateCallback = nPAeIdProtocolStateCallback;


void startSimpleClient(const nPAeIdUserInteractionCallback_t fnUserInteractionCallback_=nPAeIdUserInteractionCallback, const nPAeIdProtocolStateCallback_t fnCurrentStateCallback_ = nPAeIdProtocolStateCallback)
{
	fnUserInteractionCallback = fnUserInteractionCallback_;
	fnCurrentStateCallback = fnCurrentStateCallback_;

	struct mg_context *ctx;
	struct mg_callbacks callbacks;

	// List of options. Last element must be NULL.
	const char *options[] = {"listening_ports", "24727", NULL};
	// Prepare callbacks structure. We have only one callback, the rest are NULL.
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.begin_request = begin_request_handler;

	CivetServer civetServer = CivetServer(options, &callbacks);
	// Wait until user hits "enter". Server is running in separate thread.
	puts("Client is running...");
	sleepInfinite();
}

//Loggingfunctions
void debugOut(
	const char* format,
	...)
{
#if defined(_DEBUG) || defined(DEBUG)
	va_list params;
	va_start (params, format);

	char message[4096];
	int ret = vsprintf(message, format, params);
	eCardCore_debug(DEBUG_LEVEL_CLIENT, message);
#endif
}

void errorOut(
	const char* format,
	...)
{
	va_list params;
	va_start (params, format);

	char message[4096];
	int ret = vsprintf(message, format, params);

	eCardCore_warn(DEBUG_LEVEL_CLIENT, message);
}

void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	gError = error;
	switch(state)
	{
	case NPACLIENT_STATE_INITIALIZE:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			debugOut("nPA client successful initialized");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client initialisation failed (0x%08X)", error);
		}
		break;
	case NPACLIENT_STATE_GOT_PACE_INFO:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			debugOut("nPA client got PACE info successfully");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client got PACE info failed (0x%08X)", error);
		}
		break;
	case NPACLIENT_STATE_PACE_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			debugOut("nPA client perfomed PACE successfully");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client perform PACE failed (0x%08X)", error);
		}
		break;
	case NPACLIENT_STATE_TA_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			debugOut("nPA client perfomed TA successfully");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client perform TA failed (0x%08X)", error);
		}
		break;
	case NPACLIENT_STATE_CA_PERFORMED:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			debugOut("nPA client perfomed CA successfully");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client perform CA failed (0x%08X)", error);
		}
		break;
	case NPACLIENT_STATE_READ_ATTRIBUTES:
		if(error == NPACLIENT_ERROR_SUCCESS)
		{
			mutex_unlock(ghMutex);
			debugOut("nPA client read attribute successfully\n\n");
		}
		else
		{
			mutex_unlock(ghMutex);
			errorOut("nPA client read attributes failed (0x%08X)", error);
		}
		break;
	default:
		break;
	}
}

NPACLIENT_ERROR nPAeIdUserInteractionCallback(
	const SPDescription_t *description, UserInput_t *input)
{
	if (input->pin_required) {
		strncpy((char *) input->pin.pDataBuffer, gPin.data(), gPin.length());
		input->pin.bufferSize = gPin.length();
	}

	return nPAeIdUserInteractionCallback_ui(description, input);
}


#ifdef _WIN32
#define VCAST 
DWORD WINAPI

#else
#define VCAST (void*)
void *
#endif
performAuthenticationThread(void *lpParam)
{
	unsigned long dwWaitResult = mutex_lock(ghMutex);

	CeIdObject * authParams = (CeIdObject*) lpParam;

	NPACLIENT_ERROR rVal = nPAeIdPerformAuthenticationProtocol(READER_PCSC,
		authParams->m_strServerAddress.c_str(),
		authParams->m_strSessionID.c_str(),
		authParams->m_strPSK.c_str(),
		0x00,
		authParams->m_strTransactionURL.empty() ? NULL : authParams->m_strTransactionURL.c_str(),
		fnUserInteractionCallback,
		fnCurrentStateCallback);

	if(rVal != NPACLIENT_ERROR_SUCCESS)
	{
		errorOut("ERROR: nPAeIdPerformAuthenticationProtocolPcSc failed (0x%08X)", rVal);
		return VCAST -1;
	}
	return VCAST 0;
}

int callEcardLib(CeIdObject & tcToken)
{
#ifdef _WIN32
	HANDLE  hThread;
	DWORD   dwThreadId;

	hThread = CreateThread( 
		NULL,                   // default security attributes
		0,                      // use default stack size  
		performAuthenticationThread,       // thread function name
		&tcToken,          // argument to thread function 
		0,                      // use default creation flags 
		&dwThreadId);   // returns the thread identifier 

	if(hThread)
#else
	/* TODO thread cleanup */
	pthread_t hThread;

	if (0 == pthread_create(&hThread, NULL, performAuthenticationThread, &tcToken))
#endif
		return NPACLIENT_ERROR_SUCCESS;

	return NPACLIENT_ERROR_CREATE_THREAD;
}


#if defined(__cplusplus)
extern "C"
{
#endif
	static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
	{
		size_t realsize = size * nmemb;
		string * buf = (string*)userp;
		buf->append((char*)contents, realsize);

		return realsize;
	}
#if defined(__cplusplus)
}
#endif

static int getTcToken(string & tcToken, const string & tcTokenURL)
{
	EIDCLIENT_CONNECTION_HANDLE connection;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[0x10000];
	size_t sz_len = sizeof sz;

	connection_status = eIDClientConnectionStartHttp(&connection, tcTokenURL.c_str(), NULL, NULL, 0);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}

	connection_status = eIDClientConnectionTransceive(connection, NULL, 0 , sz, &sz_len);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}
	
	tcToken.assign(sz, sz_len);

	connection_status = eIDClientConnectionEnd(connection);
	return connection_status;
}

static int getSamlResponse(string & samlResponse, const string & refreshAddress)
{
	EIDCLIENT_CONNECTION_HANDLE connection;
	EID_CLIENT_CONNECTION_ERROR connection_status;
	char sz[0x10000];
	size_t sz_len = sizeof sz;

	connection_status = eIDClientConnectionStartHttp(&connection, refreshAddress.c_str(), NULL, NULL, 1);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}

	connection_status = eIDClientConnectionTransceive(connection, NULL, 0 , sz, &sz_len);
	if (connection_status != EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
		return connection_status;
	}

	samlResponse = std::string(sz, sz_len);

	connection_status = eIDClientConnectionEnd(connection);
	return connection_status;
}

static bool unmarshall(struct mg_connection *conn) {
	string dst;
	bool rVal = false;

	if(CivetServer::getParam(conn, "activationObject", dst)) {
		//Open eCard Legacy Activator
		if(dst.find('<') != string::npos) {
			size_t pskTag = dst.find("<PSK>");
			dst.erase(pskTag, 5);
			pskTag = dst.find("</PSK>");
			dst.erase(pskTag, 6);
			gAuthParams.GetParams(dst);
			rVal = true;
		} else {
			//filtered by NoScript
			//TODO
		}
	}

	else if (CivetServer::getParam(conn, "tcTokenURL", dst)) {
		string tcToken;
		//SAML Profile 2 First Call
		if(!getTcToken(tcToken, dst)) {
			gAuthParams.GetParams(tcToken);
			rVal = true;
		}
	}

	return rVal;
}

// This function will be called by civetweb on every new request.
static int begin_request_handler(struct mg_connection *conn) {
	const struct mg_request_info *request_info = mg_get_request_info(conn);
	const int URLLENGTH = 2049;
	const int PINLENGTH = 128;
	char tcTokenURL[URLLENGTH];
	char transactionURL[URLLENGTH];
	char cssURL[URLLENGTH];
	char pin[PINLENGTH];
	int retValue = 0;
	tcTokenURL[0] = '\0';
	transactionURL[0] = '\0';
	pin[0] = '\0';

	string samlResponse;

	if(!unmarshall(conn)) {
		return 0;
	}
	//	mg_get_var(request_info->query_string, strlen(request_info->query_string), "transactionURL", transactionURL, URLLENGTH);
	//if(transactionURL[0] != '\0')
	//{
	//	//Get the Transaction Information
	//	gAuthParams.m_strTransactionURL = transactionURL;
	//}

#if _WIN32
		ghMutex = CreateMutexA( 
			NULL,              // default security attributes
			FALSE,             // initially not owned
			NULL);			// No Name
#endif

		retValue = callEcardLib(gAuthParams);

		if(retValue == NPACLIENT_ERROR_SUCCESS) {
			/*Wait for performAuthenticationThread to lock the Mutex,
			so we can be sure to have the UserInteractionHtml*/
			sleepMilliseconds(1000);
			/*Wait until eID has finished*/
			DWORD dwWaitResult = mutex_lock(ghMutex);
			mutex_unlock(ghMutex);

			retValue = getSamlResponse(samlResponse, gAuthParams.m_strRefreshAddress);
			string transferencoding = "Transfer-Encoding:";
			string linefeeding = "\r\n\r\n";
			string header = "HTTP/1.1 200 OK\r\nContent-Type: text/html";
			//size_t found = samlResponse.find(transferencoding);
			size_t found = samlResponse.find(linefeeding);
			samlResponse.erase(0, found);
			samlResponse = header + samlResponse;
			//samlResponse.erase(found, linefeeding.length());
			mg_write(conn, samlResponse.c_str(), samlResponse.length());
		}

	return 0;
}

int main(void) {
	startSimpleClient();
	return 0;
}
