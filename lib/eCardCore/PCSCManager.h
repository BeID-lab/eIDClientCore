/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__PCSCMANAGER_INCLUDED__)
#define __PCSCMANAGER_INCLUDED__

#include "IReaderManager.h"

/*!
 * @class PCSCManager
 */
class PCSCManager : public IReaderManager
{
	private:
		void findReaders(
			void);

	public:
		/*!
		 *
		 */
		PCSCManager(
			void);

		/*!
		 *
		 */
		ECARD_PROTOCOL getProtocol() {
			return PROTOCOL_PCSC;
		};
};

#endif
