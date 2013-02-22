/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__IREADERMANAGER_INCLUDED__)
#define __IREADERMANAGER_INCLUDED__

#include "IReader.h"
#include "eCardTypes.h"

#include <string>
#include <vector>
using namespace std;

/*!
 * @class IReaderManager
 */

class IReaderManager
{
	protected:
		vector<IReader *> m_readerList;
		vector<ICardDetector *> m_cardDetectors;

	public:
		/*!
		 *
		 */
		IReaderManager(
			void) {}

		/*!
		 *
		 */
		virtual ~IReaderManager(
			void) {
			// Delete all known readers.
			for (vector<IReader *>::iterator it = m_readerList.begin();
				 it != m_readerList.end(); it++) {
				IReader *reader = *it;
				delete reader;
			}

			// Delete all known card detectors
			for (vector<ICardDetector *>::iterator it = m_cardDetectors.begin();
				 it != m_cardDetectors.end(); it++) {
				ICardDetector *detector = *it;
				delete detector;
			}
		};

		/*!
		 *
		 */
		size_t getReaderCount(
			void) {
			return m_readerList.size();
		}

		/*!
		 *
		 */
		IReader *getReader(
			size_t idx) {
			if (idx > m_readerList.size())
				return 0x0;

			return m_readerList[idx];
		}

		/*!
		 *
		 */
		vector<IReader *> getReaders(
			void) { return m_readerList; };

		/*!
		 *
		 */
		IReader *getReader(
			const string &readerName) {
			for (vector<IReader *>::iterator it = m_readerList.begin();
				 it != m_readerList.end(); it++) {
				IReader *reader = *it;

				if (reader->getReaderName().compare(readerName) == 0)
					return reader;
			}

			return 0x0;
		}

		/*!
		 *
		 */
		void addCardDetector(
			ICardDetector *detector) {
			m_cardDetectors.push_back(detector);
		}

		// -------------------------------------------------------------------------
		// Pure virtuals
		// -------------------------------------------------------------------------

		/*!
		 *
		 */
		virtual ECARD_PROTOCOL getProtocol(
			void) = 0;
};

#endif
