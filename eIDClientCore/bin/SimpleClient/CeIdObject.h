#ifndef _CEIDOBJECT_H_
#define _CEIDOBJECT_H_
#include <string>

#define XML_STATIC
#include <expat.h>

class CeIdObject
{
public:
	CeIdObject();
	~CeIdObject(void);

public:
	bool GetParams(std::string strToParse);

protected:
	static void StartElementHandler(void *pUserData, const XML_Char *pszName, const XML_Char **papszAttrs);
	static void EndElementHandler(void *pUserData, const XML_Char *pszName);
	static void CharacterDataHandler(void *pUserData, const XML_Char *pszName, int len);
	void OnStartElement(const XML_Char *pszName, const XML_Char **papszAttrs);
	void OnEndElement(const XML_Char *pszName);
	void OnCharacterData(const XML_Char *pszName, int len);

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
	std::string  m_strTransactionURL;

protected:
	std::string m_strCurrentElement;
	std::string m_strRootElement;
};

#endif //_CEIDOBJECT_H_