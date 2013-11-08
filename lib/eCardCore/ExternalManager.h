/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#if !defined(__EXTERNALMANAGER_INCLUDED__)
#define __EXTERNALMANAGER_INCLUDED__

#include "IReaderManager.h"
#include "ExternalReader.h"

class ExternalManager : public IReaderManager
{
	public:
		ExternalManager(void)
		{
	        m_readerList.push_back(new ExternalReader("ExternalReader", m_cardDetectors));
		}

		ECARD_PROTOCOL getProtocol()
	   	{ 
			return PROTOCOL_EXTERNAL;
	   	};
};

#endif // __EXTERNALMANAGER_INCLUDED__
