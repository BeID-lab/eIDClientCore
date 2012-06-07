#ifndef __eIdECardClient_H__
#define __eIdECardClient_H__

#include <string>
#include <sstream>
#include <list>

#define XML_STATIC
#include <expat.h>

#include "nPAClient.h"
using namespace Bundesdruckerei::nPA;

#include "eIdClientCoreLib.h"

using namespace std;

typedef list<string>	certificateList_t;
typedef list<string>	APDUList_t;

#include <time.h>

#include "eIDClientConnection.h"

class eIdECardClient : public IIdP
{
public:
	eIdECardClient();
    eIdECardClient(CharMap* paraMap);

	~eIdECardClient(void);

      eIdECardClient& operator=(const eIdECardClient&);

      static eIdECardClient* createInstance(CharMap* paraMap);

      bool open(void);
      bool close(void);

      /*!
       *
       */
      NPACLIENT_ERROR initialize(
        const CharMap* paraMap,
        IClient* pClient);

      /**
       *
       */
      ByteData getTerminalCertificate(
        void) { return m_TerminalCertificate; }

      /**
       *
       */
      ByteData getRequiredChat(
        void) { return m_RequiredCHAT; }

	  /**
       *
       */
      ByteData getOptionalChat(
		  void) { return m_OptionalCHAT; }
 
      /**
       *
       */
      ByteData getDVCACertificate(
        void) { return m_DVCACertificate; }

      /**
       *
       */
      ByteData getAuthenticatedAuxiliaryData(
        void) { return m_AuthenticatedAuxiliaryData; }

      /**
       *
       */
      ByteData getCertificateDescription(
        void) { return m_CertificateDescription; }

      /**
       *
       */
      bool getTerminalAuthenticationData(
        std::vector<unsigned char> efCardAccess,
        std::vector<unsigned char> chat,
        std::string cvCACHAR,
        std::vector<unsigned char> idPICC,
        std::vector<unsigned char>& dvcaCertificate,
        std::vector<unsigned char>& x_Puk_IFD_DH_CA_,
        std::vector<unsigned char>& y_Puk_IFD_DH_CA_);

      /**
       *
       */
      bool createSignature(
        std::vector<unsigned char> toBeSigned,
        std::vector<unsigned char>& signature);

      /**
       *
       */
      bool finalizeAuthentication(
        std::vector<unsigned char> efCardSecurity,
        std::vector<unsigned char> GAResult,
        std::vector<std::vector<unsigned char> >& apdus);

      /**
       *
       */
      bool readAttributes(
        std::vector<std::vector<unsigned char> > apdus);
	
	private:
		  static eIdECardClient*	m_instance;
		  IClient*					m_pClient;

		std::string	m_strServerAddress;
		std::string	m_strSessionIdentifierN;
		std::string	m_strPathSecurityParameter;

	   // The terminal certificate of the relying party.
       ByteData m_TerminalCertificate;
       // The certificate description for the certificate of the relying party.
       ByteData m_CertificateDescription;
       //
       ByteData m_DVCACertificate;
       // The session ID for this run.
       ByteData m_sessionID;
       // The required CHAT.
       ByteData m_RequiredCHAT;
       // The optional requested CHAT.
       ByteData m_OptionalCHAT;
       // The authenticated auxilary data for RI and the likes.
       ByteData m_AuthenticatedAuxiliaryData;
       // The last recieved messages uuid.
       string m_strLastMsgUUID;

protected:

	bool StartConnection(const char* url, const string &strSessionIdentifier, const string &strPSKKey);
	void EndConnection();

	void StartPAOS( const string &strSessionID,
					string &strRequiredChat,
					string &strOptionalChat,
					string &strAuxiliaryData,
					string &strCertificate,
					string &strCertificateDescription,
					string &strNewMessageID);
	void PACEResponse(	const string &strMessageID,
						const string &strUserChat,
						const string &strCertRef,
						const string &strEFCardAccess,
						const string &strIDPICC,
						string &strEphemeralPublicKey,
						certificateList_t &CertList,
						string &strNewMessageID);
	void TAResponse(const string &strMessageID, 
					const string &strChallenge,
					string &strSignature,
					string &strNewMessageID);
	void CAResponse(const string &strMessageID,
					const string &strEFCardSecurity,
					const string &strAuthenticationToken,
					const string &strNonce,
					APDUList_t &APDUList,
					string &strNewMessageID);
	void TransmitResponse(	const string &strMessageID,
							const APDUList_t &inAPDUList,
							APDUList_t &outAPDUList);

public:
	void OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs);
	void OnEndElement(const XML_Char *pszName);
	void OnCharacterData(const XML_Char *pszData, int nLength);

protected:
	static void StartElementHandler (void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);
	static void EndElementHandler(void *pUserData, const XML_Char *pszName);
	static void CharacterDataHandler(void *pUserData, const XML_Char *pszData, int nLength);

private:
	void WriteStartPaos(::stringstream &oss, const string &strSessionID);
	void WriteEAC1Output(::stringstream &oss, const string &strMessageID, const string &strUserChat, const string &strCertRef, const string &strEFCardAccess, const string &strIDPICC);
	void WriteEAC2OutputChallenge(::stringstream &oss, const string &strMessageID, const string &strChallenge);
	void WriteEAC2OutputCardSecurity(::stringstream &oss, const string &strMessageID, const string &strEFCardSecurity, const string &strAuthenticationToken, const string &strNonce);
	void WriteOutputAPDU(::stringstream &oss, const string &strMessageID, const APDUList_t &APDUList);
	void WriteDIDAuthenticateResponse(::stringstream &oss, stringstream &ssOutputType, const string &strMessageID);
	void WriteTransmitResponse(::stringstream &oss, stringstream &ssOutputAPDU, const string &strMessageID);
	void WriteInitializeFrameworkResponse(::stringstream &oss, const string &strMessageID);

	void WritePAOS_Response(::stringstream &oss, stringstream &ss, const string &strRelatesTo = string(""));

	string	request_post(const string& in);
	string  request_get_PAOS();

	string getRandomStringID(int nCount);
	bool parse_url(const char* str, const char* default_port="80");

	bool doParse(const string &strXML);

private:
	string	m_strMessageID;

	string	m_strRequiredChat;
	string	m_strOptionalChat;
	string	m_strAuxiliaryData;
	string	m_strCertificateDescription;

	string				m_strEphemeralPublicKey;
	certificateList_t	m_certificateList;

	string	m_strSignature;

	APDUList_t			m_APDUList;

	string	m_strCurrentTag;

	string		m_strSessionIdentifier;

	string	m_strScheme;
	string	m_strHostname;
	string	m_strPort;
	string	m_strPath;

	EIDCLIENT_CONNECTION_HANDLE	m_hConnection;
};

#endif // __eIdECardClient_H__
