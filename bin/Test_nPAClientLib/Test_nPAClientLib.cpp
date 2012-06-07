// Test_nPAClientLib.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#if defined(WIN32)
#	include <windows.h>
#	include <tchar.h>
#   include <wininet.h>
#   include <wincrypt.h>
#else
# define WINAPI
# include <pthread.h>
#endif

#define	READ_BUFFER	8192
#define	AGENTNAME	"eIdBdrClient"

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <vector>
#include <iomanip>
#include <string.h>
#include <sstream>

#define XML_STATIC
#include <expat.h>

#include <eIdClientCoreLib.h>
#include <eCardTypes.h>
#include <eIDClientConnection.h>

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

#ifdef _WIN32
DWORD
#else
void *
#endif
WINAPI getSamlResponseThread( LPVOID lpParam )
{
    URL	urlIDP(strRefresh.c_str());

    string	strResult = "";
    EIDCLIENT_CONNECTION_HANDLE connection;
    EID_CLIENT_CONNECTION_ERROR connection_status;
    char sz[READ_BUFFER];

    connection_status = eIDClientConnectionStart(&connection, urlIDP._hostname.c_str(),
            urlIDP._port.c_str(), urlIDP._path.c_str(), 0, NULL);
    if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS)
    {
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
                get.c_str(), sz, sizeof sz);
        if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
            strResult += sz;
            strResult = strResult.substr(strResult.find("<html"));
        }
    }
    connection_status = eIDClientConnectionEnd(connection);

    cout << strResult << endl;

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
							const char* const pPort,
							const char* const cPath,
							string &strIdpAddress,
							string &strSessionIdentifier,
							string &strPathSecurityParameters)
{
  string	strResult = "";
  EIDCLIENT_CONNECTION_HANDLE connection;
  EID_CLIENT_CONNECTION_ERROR connection_status;
  char sz[READ_BUFFER];

  connection_status = eIDClientConnectionStart(&connection,
          cServerName, pPort, cPath, 0, NULL);
  if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS)
  {
      /* Send a GET request */
      string get("GET ");
      get += cPath;
      get += " HTTP/1.1\r\n";

      get += "Host: ";
      get += cServerName;
      get += cPath;
      get += ":";
      get += pPort;
      get += "\r\n\r\n";

      connection_status = eIDClientConnectionSendRequest(connection,
              get.c_str(), sz, sizeof sz);
      if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
          strResult += sz;
          strResult = strResult.substr(strResult.find("<html"));
      }
  }
  eIDClientConnectionEnd(connection);

  CeIdObject		eIdObject;

  eIdObject.GetParams(strResult);

  cout << "Action is\t" << eIdObject.m_strAction.c_str() << endl;
  cout << "Method is\t" << eIdObject.m_strMethod.c_str() << endl;
  cout << "SAMLRequest is\t" << eIdObject.m_strSAMLRequest.c_str() << endl;
  cout << "SigAlg is\t" << eIdObject.m_strSigAlg.c_str() << endl;
  cout << "Signature is\t" << eIdObject.m_strSignature.c_str() << endl;
  cout << "RelayState is\t" << eIdObject.m_strRelayState.c_str() << endl;

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
  std::stringstream out;
  out << strData.length();
  string strContentLength = "Content-Length: " + out.str();

  strResult = "";
  connection_status = eIDClientConnectionStart(&connection,
          urlIDP._hostname.c_str(), "443", urlIDP._path.c_str(),
          0, NULL);
  if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS)
  {
      string request;
      if (strcmp(eIdObject.m_strMethod.c_str(), "post") == 0) {
          /* Send a POST request */
          request += "POST ";
      } else {
          /* Send a GET request */
          request += "GET ";
      }
      request += urlIDP._path + " HTTP/1.1\r\n";

      request += "Host: " + urlIDP._hostname + ":" + "443" + "\r\n";
      request += strContentType + "\r\n";
      request += strContentLength + "\r\n\r\n";

      request += strData;

      connection_status = eIDClientConnectionSendRequest(connection,
              request.c_str(), sz, sizeof sz);
      if(connection_status == EID_CLIENT_CONNECTION_ERROR_SUCCESS) {
          strResult += sz;

          strResult = strResult.substr(strResult.find("<HTML"));
      }
  }
  eIDClientConnectionEnd(connection);

  string response2 = strResult;

  response2 = str_replace("<PSK>", "", response2);
  response2 = str_replace("</PSK>", "", response2);
  response2 = str_replace("&uuml;", "ü", response2);
  response2 = str_replace("&ouml;", "ö", response2);

  eIdObject.GetParams(response2);

  strIdpAddress = eIdObject.m_strServerAddress;
  strSessionIdentifier = eIdObject.m_strSessionID;
  strPathSecurityParameters = eIdObject.m_strPSK;

  cout << "IdpAddress is\t" + strIdpAddress + "\n";
  cout << "SessionIdentifier is\t" + strSessionIdentifier + "\n";
  cout << "PathSecurityParameters is\t" + strPathSecurityParameters + "\n";

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
	
  while (0 == retValue)
  {
    time_t start;
    time(&start);

    string strIdpAddress = "";
    string strSessionIdentifier = "";
    string strPathSecurityParameters = "";
	string strRef = "";

	getAuthenticationParams("eidservices.bundesdruckerei.de", "443", "/ExampleSP/saml/Login", strIdpAddress, strSessionIdentifier, strPathSecurityParameters);

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

