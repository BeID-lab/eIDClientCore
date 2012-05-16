// Test_nPAClientLib.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#if defined(WIN32)
#	include <windows.h>
#	include <tchar.h>
# define LOAD_LIBRARY(libName)						LoadLibrary(libName)
# define GET_FUNCTION(hModule, funcName)	GetProcAddress((HMODULE) hModule, funcName)
# define FREE_LIBRARY(hModule)						FreeLibrary((HMODULE) hModule)
#endif

#if defined(__APPLE__)
# include <dlfcn.h>
# define LOAD_LIBRARY(libName)					  dlopen(libName, RTLD_LAZY)
# define GET_FUNCTION(hModule, funcName)	dlsym(hModule, funcName)
# define FREE_LIBRARY(hModule)						dlclose(hModule)
#endif

#define	READ_BUFFER	8192
#define	AGENTNAME	"eIdBdrClient"

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <vector>
#include <iomanip>

#include <windows.h>
#include <Wininet.h>
#include <wincrypt.h>

#define XML_STATIC
#include <expat.h>

#include <eIdClientCoreLib.h>

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
	static void StartElementHandler (void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);

public:
	string	m_strAction;
	string	m_strMethod;
	string	m_strSAMLRequest;
	string	m_strSigAlg;
	string	m_strSignature;
	string	m_strRelayState;

	string	m_strSessionID;
	string	m_strPSK;
	string	m_strRefreshAddress;
	string	m_strServerAddress;
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
	CeIdObject* pThis = (CeIdObject*) pUserData;
	pThis ->OnStartElement (pszName, papszAttrs);
}

void CeIdObject::OnStartElement (const XML_Char *pszName, const XML_Char **papszAttrs)
{
	string	strCurrentTag(pszName);
	string	strParamName = "";
	string	strParamValue = "";

	printf ("We got a start element %s\n",strCurrentTag.c_str());
	if( strcmp(strCurrentTag.c_str(), "param") == 0 )
	{
		for (int i=0; papszAttrs[i]; i+=2)
        {
			string	strParam(papszAttrs[i]);
			if( strcmp(strParam.c_str(), "name") == 0 )
			{
				strParamName.assign(papszAttrs[i+1]);
			}
			else if( strcmp(strParam.c_str(), "value") == 0 )
			{
				if( strcmp(strParamName.c_str(), "SessionIdentifier") == 0 )
				{
					m_strSessionID.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "PathSecurity-Parameters") == 0 )
				{
					m_strPSK.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "RefreshAddress") == 0 )
				{
					m_strRefreshAddress.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "ServerAddress") == 0 )
				{
					m_strServerAddress.assign(papszAttrs[i+1]);
				}
			}
		}
	}
	if( strcmp(strCurrentTag.c_str(), "form") == 0 )
	{
		for (int i=0; papszAttrs[i]; i+=2)
        {
			string	strParam(papszAttrs[i]);
			if( strcmp(strParam.c_str(), "action") == 0 )
			{
				m_strAction.assign(papszAttrs[i+1]);
				printf("action: %s \n", m_strAction.c_str());
			}
			else if( strcmp(strParam.c_str(), "method") == 0 )
			{
				m_strMethod.assign(papszAttrs[i+1]);
				printf("method: %s \n", m_strMethod.c_str());
			}
		}
	}
	if( strcmp(strCurrentTag.c_str(), "input") == 0 )
	{
		for (int i=0; papszAttrs[i]; i+=2)
        {
			printf("%s : %s \n", papszAttrs[i], papszAttrs[i+1]);

			string	strParam(papszAttrs[i]);
			if( strcmp(strParam.c_str(), "type") == 0 )
			{
//				strParamName.assign(papszAttrs[i+1]);
			}
			else if( strcmp(strParam.c_str(), "name") == 0 )
			{
				strParamName.assign(papszAttrs[i+1]);
			}
			else if( strcmp(strParam.c_str(), "value") == 0 )
			{
				if( strcmp(strParamName.c_str(), "SAMLRequest") == 0 )
				{
					m_strSAMLRequest.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "SigAlg") == 0 )
				{
					m_strSigAlg.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "Signature") == 0 )
				{
					m_strSignature.assign(papszAttrs[i+1]);
				}
				else if( strcmp(strParamName.c_str(), "RelayState") == 0 )
				{
					m_strRelayState.assign(papszAttrs[i+1]);
				}
			}
		}
	}
	return;
}

void CeIdObject::GetParams(string strToParse)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser,(void*) this );
	XML_SetStartElementHandler (parser, StartElementHandler);
	XML_Parse(parser, strToParse.c_str(), strToParse.length(), true);	
	XML_ParserFree(parser);	
}

class URL
{
public:
	URL(const char* url)
	{
		parse_url(url);
	}
	
	string	_scheme;
	string	_hostname;
	string	_port;
	string	_path;
    
	bool parse_url(const char* str, const char* default_port="80")
	{
		if (!str || !*str)
			return false;
        
		const char* p1 = strstr(str, "://");
        
		if (p1)
		{
			_scheme.assign(str, p1-str);
			p1 += 3;
		}
		else
		{
			p1 = str;
		}
        
		const char* p2 = strchr(p1, ':');
        //		const char* p3 = p2 ? strchr(p2+1, '/'): p2;
		const char* p3 = strchr(p1, '/');
        
		if (p2)
		{
			_hostname.assign(p1, p2-p1);
			if (p3)
			{
                _port.assign(p2+1, p3-(p2+1));
                _path = p3;
			}
			else
			{
                _port.assign(p2+1);
			}
		} 
		else 
		{
			_port = default_port;
			if (p3)
			{
			    _hostname.assign(p1, p3-p1);
			    _path = p3;
			}
			else
			{
				_hostname = p1;
			}
		}
        
		if (_path.empty())
			_path = "";
        
		return true;
	}
};


string strRefresh = "";

DWORD WINAPI getSamlResponseThread( LPVOID lpParam )
{
  URL	urlIDP(strRefresh.c_str());

  string	strResult = "";
  int		secureFlags = INTERNET_FLAG_RELOAD|INTERNET_FLAG_KEEP_CONNECTION|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
  HINTERNET	hSession = 0x00;
  HINTERNET	hConnect = 0x00;
  HINTERNET	hRequest = 0x00;

  hSession = InternetOpen(AGENTNAME, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if(hSession)
  {
	hConnect = InternetConnect(hSession, urlIDP._hostname.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if(hConnect)
    {
	  hRequest = HttpOpenRequest(hConnect, "GET", urlIDP._path.c_str(), NULL, "", NULL, secureFlags, 0);
	  if(hRequest)
	  {
        DWORD dwFlags;
        DWORD dwBuffLen = sizeof(dwFlags);
        
		InternetQueryOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS,&dwFlags, sizeof (dwFlags) );

        int result =  HttpSendRequest(hRequest, NULL, 0, NULL, 0);
        DWORD dwNumberOfBytesRead;
        char sz[READ_BUFFER];
        do
        {
          result = InternetReadFile(hRequest, sz, READ_BUFFER - 1, &dwNumberOfBytesRead);												
          sz[dwNumberOfBytesRead] = '\0';
          int x = strlen(sz);
          strResult += sz;
          memset(sz, 0, READ_BUFFER);	
        }
        while(result && dwNumberOfBytesRead != 0);	
        InternetCloseHandle(hRequest);
		hRequest = 0x00;
      }
	  InternetCloseHandle(hConnect);
	  hConnect = 0x00;
    }
    InternetCloseHandle(hSession);
	hSession = 0x00;
  }

  cout << strResult.c_str() << endl;

  return 0;
}

void nPAeIdProtocolStateCallback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error)
{
	switch(state)
	{
		case NPACLIENT_STATE_INITIALIZE:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
				std::cout << "nPA client successful initialized" << std::endl;
			}
			else
			{
				std::cout << "nPA client initialisation failed with code : " << HEX(error) << std::endl;
			}
		  break;
		case NPACLIENT_STATE_GOT_PACE_INFO:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
			    std::cout << "nPA client got PACE info successfully" << std::endl;
			}
			else
			{
				std::cout << "nPA client got PACE info failed with code : " << HEX(error) << std::endl;
			}
		  break;
		case NPACLIENT_STATE_PACE_PERFORMED:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
			  std::cout << "nPA client perfomed PACE successfully" << std::endl;
			}
			else
			{
			  std::cout << "nPA client perform PACE failed with code : " << HEX(error) << std::endl;
			}
		  break;
		case NPACLIENT_STATE_TA_PERFORMED:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
			  std::cout << "nPA client perfomed TA successfully" << std::endl;
			}
			else
			{
			  std::cout << "nPA client perform TA failed with code : " << error << std::endl;
			}
		  break;
		case NPACLIENT_STATE_CA_PERFORMED:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
			  std::cout << "nPA client perfomed CA successfully" << std::endl;
			}
			else
			{
			  std::cout << "nPA client perform CA failed with code : " << HEX(error) << std::endl;
			}
			HANDLE  hThread;
			DWORD   dwThreadId;
			hThread = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            getSamlResponseThread,       // thread function name
            NULL,          // argument to thread function 
            0,                      // use default creation flags 
            &dwThreadId);   // returns the thread identifier 

		  break;
		case NPACLIENT_STATE_READ_ATTRIBUTES:
			if(error == NPACLIENT_ERROR_SUCCESS)
			{
			  std::cout << "nPA client read attribute successfully" << std::endl;
			}
			else
			{
			  std::cout << "nPA client read attributes failed with code : " << HEX(error) << std::endl;
			}
		  break;
		default:
			break;
	}
}

NPACLIENT_ERROR nPAeIdUserInteractionCallback(
  const long long chatFromCertificate,
  const long long chatRequired,
  const long long chatOptional,
  const char* const certificateDescription,
  const char* const serviceName,
  const char* const serviceURL,
  long long& chatUserSelected,
  char* const bufPIN,
  const int nBufLength)
{
  std::cout << "certificateDescription : " << certificateDescription << std::endl;
  std::cout << "serviceName : " << serviceName << std::endl;
  std::cout << "serviceURL : " << serviceURL << std::endl;
  
  chatUserSelected = chatFromCertificate;
  memset(bufPIN, 0x00, nBufLength);
  strcpy(bufPIN,"123456");

  return NPACLIENT_ERROR_SUCCESS;
}

string str_replace (string rep, string wit, string in)
{
  int pos;
  while (true)
  {
    pos = in.find(rep);
    if (pos == -1) 
	{
      break;
    } 
	else 
	{
      in.erase(pos, rep.length());
      in.insert(pos, wit);
    }
  }
  return in;
}

int getAuthenticationParams(const char* const cServerName,
							const unsigned short pPort,
							const char* const cPath,
							const char* const cUserName,
							const char* const cPassWord,
							string &strIdpAddress,
							string &strSessionIdentifier,
							string &strPathSecurityParameters)
{
  string	strResult = "";
  int		secureFlags = INTERNET_FLAG_RELOAD|INTERNET_FLAG_KEEP_CONNECTION|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
  HINTERNET	hSession = 0x00;
  HINTERNET	hConnect = 0x00;
  HINTERNET	hRequest = 0x00;

  hSession = InternetOpen(AGENTNAME, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if(hSession)
  {
    if( (cUserName != 0x00) && (cPassWord != 0x00) )
	{
	  hConnect = InternetConnect(hSession, cServerName, pPort, cUserName, cPassWord, INTERNET_SERVICE_HTTP, 0, 0);
	}
	else
	{
	  hConnect = InternetConnect(hSession, cServerName, pPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	}
    if(hConnect)
    {
      hRequest = HttpOpenRequest(hConnect, "GET", cPath, NULL, "", NULL, secureFlags, 0);
	  if(hRequest)
	  {
        DWORD dwFlags;
        DWORD dwBuffLen = sizeof(dwFlags);
        
		InternetQueryOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);
        dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS,&dwFlags, sizeof (dwFlags) );

        int result =  HttpSendRequest(hRequest, NULL, 0, NULL, 0);
        DWORD dwNumberOfBytesRead;
        char sz[READ_BUFFER];
        do
        {
          result = InternetReadFile(hRequest, sz, READ_BUFFER - 1, &dwNumberOfBytesRead);												
          sz[dwNumberOfBytesRead] = '\0';
          int x = strlen(sz);
          strResult += sz;
          memset(sz, 0, READ_BUFFER);	
        }
        while(result && dwNumberOfBytesRead != 0);	
        InternetCloseHandle(hRequest);
		hRequest = 0x00;
      }
	  InternetCloseHandle(hConnect);
	  hConnect = 0x00;
    }
    InternetCloseHandle(hSession);
	hSession = 0x00;
  }

  cout << strResult.c_str() << endl;

  CeIdObject		eIdObject;

  eIdObject.GetParams(strResult);

  cout << eIdObject.m_strAction.c_str() << endl;
  cout << eIdObject.m_strMethod.c_str() << endl;
  cout << eIdObject.m_strSAMLRequest.c_str() << endl;
  cout << eIdObject.m_strSigAlg.c_str() << endl;
  cout << eIdObject.m_strSignature.c_str() << endl;
  cout << eIdObject.m_strRelayState.c_str() << endl;

  URL	urlIDP(eIdObject.m_strAction.c_str());
  string strContentType = "Content-Type: application/x-www-form-urlencoded";
  string strData = "SAMLRequest=";
  strData += eIdObject.m_strSAMLRequest;
  strData += "&SigAlg=";
  strData += eIdObject.m_strSigAlg;
  strData += "&Signature=";
  strData += eIdObject.m_strSignature;
  if(eIdObject.m_strRelayState.size() > 1)
  {
    strData += "&RelayState=";
    strData += eIdObject.m_strRelayState;
  }

  secureFlags = INTERNET_FLAG_RELOAD|INTERNET_FLAG_KEEP_CONNECTION|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_PRAGMA_NOCACHE|INTERNET_FLAG_SECURE;

  strResult = "";
  hSession = InternetOpen(AGENTNAME, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if(hSession)
  {
    hConnect = InternetConnect(hSession, urlIDP._hostname.c_str(), INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if(hConnect)
    {
      hRequest = HttpOpenRequest(hConnect, "POST", urlIDP._path.c_str(), NULL, "", NULL, secureFlags, 0);
//      hRequest = HttpOpenRequest(hConnect, "POST", urlIDP._path.c_str(), NULL, "", NULL, INTERNET_FLAG_KEEP_CONNECTION, 0);
      if(hRequest)
	  {
//        char cookie[]="Cookie: cookie1=1;cookie2=2"; 
//        HttpAddRequestHeaders(hRequest, cookie, (TCHAR)-1L, HTTP_ADDREQ_FLAG_REPLACE);
// Create a session cookie.

//		bool  bReturn = InternetSetCookie(urlIDP._hostname.c_str(), NULL, TEXT("TestData = Test"));

        DWORD dwSecFlags;
        DWORD dwSecBuffLen = sizeof(dwSecFlags);
        InternetQueryOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwSecFlags, &dwSecBuffLen);
        dwSecFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        InternetSetOption (hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof (dwSecFlags) );
        int result =  HttpSendRequest(hRequest, strContentType.c_str(), strlen(strContentType.c_str()), (void *)strData.c_str(), strlen(strData.c_str()));
		if(result)
		{
          DWORD dwNumberOfBytesRead;
          char sz[READ_BUFFER];
          do
          {
            result = InternetReadFile(hRequest, sz, READ_BUFFER - 1, &dwNumberOfBytesRead);												
            sz[dwNumberOfBytesRead] = '\0';
            int x = strlen(sz);
            strResult += sz;
            memset(sz, 0, READ_BUFFER);	
          }
          while(result && dwNumberOfBytesRead != 0);
		}
		else
		{
          int lastErr = GetLastError();
		  cout << "HttpSendRequest returns with error code : " << lastErr << endl;
		}
        InternetCloseHandle(hRequest);
		hRequest = 0x00;
      }
      InternetCloseHandle(hConnect);
	  hConnect = 0x00;
    }
    InternetCloseHandle(hSession);
	hSession = 0x00;
  }

  string response2 = strResult;
	
  cout << response2.c_str() << endl;

  response2 = str_replace("<PSK>", "", response2);
  response2 = str_replace("</PSK>", "", response2);
  response2 = str_replace("&uuml;", "ü", response2);
  response2 = str_replace("&ouml;", "ö", response2);

  eIdObject.GetParams(response2);

  strIdpAddress = eIdObject.m_strServerAddress;
  strSessionIdentifier = eIdObject.m_strSessionID;
  strPathSecurityParameters = eIdObject.m_strPSK;

  strRefresh = eIdObject.m_strRefreshAddress;

  return 0;
}

int main(int argc, char** argv)
{
  int loopCount = 10;

  int retValue = 0;
  int serverErrorCounter = 0;
  char buffer[500];

  std::vector<double> diffv;
  
  // Load the library
  void* hClientUI = 0x00;

#if defined(WIN32)
#if defined(_DEBUG) || defined(DEBUG)
  hClientUI = LOAD_LIBRARY(_T("eIdClientCored.dll"));
#else
  hClientUI = LOAD_LIBRARY(_T("eIdClientCore.dll"));
#endif
#endif	
#if defined(__APPLE__)
	hClientUI = LOAD_LIBRARY("nPAClientECardLib.dylib");
#endif
	
  if (0x00 == hClientUI)
  {
    std::cout << "ERROR: Could not load nPAClientECardLib library." << std::endl;
#if defined(__APPLE__)	
    std::cout << dlerror() << std::endl;
#endif
    return 0x00;
  }
	
//  assert(0x00 != hClientUI);

  nPAeIdPerformAuthenticationProtocolPcSc_t nPAeIdPerformAuthenticationProtocolPcSc = (nPAeIdPerformAuthenticationProtocolPcSc_t) GET_FUNCTION(hClientUI, "nPAeIdPerformAuthenticationProtocolPcSc");
//  assert(0x00 != nPAeIdPerformAuthenticationProtocolPcSc_t);

  while (0 == retValue)
  {
    time_t start;
    time(&start);

    string strIdpAddress = "";
    string strSessionIdentifier = "";
    string strPathSecurityParameters = "";
	string strRef = "";

	getAuthenticationParams("eidservices.bundesdruckerei.de", 443, "/ExampleSP/saml/Login", NULL, NULL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters);

	retValue = nPAeIdPerformAuthenticationProtocolPcSc(strIdpAddress.c_str(), strSessionIdentifier.c_str(), strPathSecurityParameters.c_str(), nPAeIdUserInteractionCallback, nPAeIdProtocolStateCallback);

	diffv.push_back(difftime(time(0x00), start));

    sprintf(buffer, " - Read Count: %d - Server Errors: %d\n", diffv.size(), serverErrorCounter);
    
	std::cout << "########## Error Code: " << HEX(retValue) << buffer << std::endl;
    
    if(diffv.size() == loopCount)
      break;
  }
  
  vector<double>::iterator it;
  double diffSum = 0;
  for(it = diffv.begin(); it != diffv.end(); ++it)
  {
    diffSum += *it;
  }
  std::cout << "Durchschnittliche Dauer bei " << diffv.size() << " Durchlaeufen: " << diffSum / diffv.size() << " Sekunden" << std::endl;

  sprintf(buffer, "########## Error Code: %X - Read Count: %d - Server Errors: %d\n", retValue, diffv.size(), serverErrorCounter);
  
  std::cout << buffer << std::endl;

  getchar();

  return retValue;
}

