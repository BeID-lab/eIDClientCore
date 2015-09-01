#include "CeIdObject.h"
#include <string.h>

using namespace std;

CeIdObject::CeIdObject()
{
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
	//Current Element
	string  strElement = pszName;

	if(m_strRootElement.empty()) {
		m_strRootElement.assign(strElement);
	}

	//We have an eCard-Object, save State for subelements
	if(!strElement.compare("object")) {
		for (int i = 0; papszAttrs[i]; i += 2) {
			string strParam(papszAttrs[i]);

			if (!strParam.compare("type")) {
				if(!strcmp(papszAttrs[i + 1], "application/vnd.ecard-client")) {
					m_strCurrentElement.assign(pszName);
					return;
				}

			}
		}
	}

	//Object Tag
	if(!m_strCurrentElement.compare("object")) {
		if (!strElement.compare("param")) {
			string  strParamName = "";
			string  strParamValue = "";
			for (int i = 0; papszAttrs[i]; i += 2) {
				string  strParam(papszAttrs[i]);

				if (!strParam.compare("name")) {
					strParamName.assign(papszAttrs[i + 1]);
				} 
				else if(!strParam.compare("value")) {
					strParamValue.assign(papszAttrs[i + 1]);
				}
				
				if(strParamName.empty() || strParamValue.empty()) {
					continue;
				}

				if (!strParamName.compare("SessionIdentifier")) {
					m_strSessionID.assign(strParamValue);

				} else if (!strParamName.compare("PathSecurity-Parameters")) {
					m_strPSK.assign(strParamValue);

				} else if (!strParamName.compare("RefreshAddress")) {
					m_strRefreshAddress.assign(strParamValue);
					/*Some eID-Servers use this CDATA "Flag" to
					* tell the XML-Parser that the following URL shouldnt be parsed */
					size_t cDataPos = m_strRefreshAddress.find("<![CDATA[");
					if(cDataPos != string::npos)
					{
						/* 9 == strlen("<![CDATA[") .... 3 == strlen("]]>") */
						m_strRefreshAddress = m_strRefreshAddress.substr(cDataPos + 9, m_strRefreshAddress.length() - 9 - 3);
					}

				} else if (!strParamName.compare("ServerAddress")) {
					m_strServerAddress.assign(strParamValue);
				}
			}
			return;
		}
	}

	//Element inside a TCToken Element
	if(!m_strRootElement.compare("TCTokenType")) {
		m_strCurrentElement.assign(strElement);
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

	else if(!m_strCurrentElement.compare("RefreshAddress") && m_strRefreshAddress.empty())
		m_strRefreshAddress = string(pszName, pszName+len);

	else if(!m_strCurrentElement.compare("PSK"))
		m_strPSK = string(pszName, pszName+len);

	return;

}

bool CeIdObject::GetParams(string strToParse)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, (void *) this);
	XML_SetStartElementHandler(parser, StartElementHandler);
	XML_SetEndElementHandler(parser, EndElementHandler);
	XML_SetCharacterDataHandler(parser, CharacterDataHandler);
	XML_Status status = XML_Parse(parser, strToParse.c_str(), strToParse.length(), true);
	XML_ParserFree(parser);
	return status == XML_STATUS_OK;
}
