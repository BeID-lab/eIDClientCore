// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: IReaderManager.h 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file IReaderManager.h
 */

#if !defined(__IREADERMANAGER_INCLUDED__)
#define __IREADERMANAGER_INCLUDED__

#include <eCardTypes.h>

#include "IReader.h"
#include "ICardDetector.h"
#include "CardCommand.h"

#include <vector>
using namespace std;

/*!
 * @class IReaderManager
 */

class IReaderManager
{
  protected:
    vector<IReader*> m_readerList;
    vector<ICardDetector*> m_cardDetectors;

  public:
    /*!
     *
     */
    IReaderManager(
      void) {}

    /*!
     *
     */
    virtual ~IReaderManager (
      void )
    {
      // Delete all known readers.

      for ( vector<IReader*>::iterator it = m_readerList.begin();
            it != m_readerList.end(); it++ )
      {
        IReader* reader = *it;
        delete reader;
      }

      // Delete all known card detectors
      for ( vector<ICardDetector*>::iterator it = m_cardDetectors.begin();
            it != m_cardDetectors.end(); it++ )
      {
        ICardDetector* detector = *it;
        delete detector;
      }
    };

    /*!
     *
     */
    size_t getReaderCount (
      void )
    {
      return m_readerList.size();
    }

    /*!
     *
     */
    IReader* getReader (
      int idx )
    {
      if ( ( size_t ) idx > m_readerList.size() )
        return 0x0;

      return m_readerList[idx];
    }

    /*!
     *
     */
    IReader* getReader (
      const string& readerName )
    {
      for (vector<IReader*>::iterator it = m_readerList.begin();
          it != m_readerList.end(); it++)
      {
          IReader* reader = *it;
          if (reader->getReaderName().compare(readerName) == 0)
            return reader;
      }

      return 0x0;
    }

    /*!
     *
     */
    void addCardDetector (
      ICardDetector* detector )
    {
      m_cardDetectors.push_back ( detector );
    }

    // -------------------------------------------------------------------------
    // Pure virtuals
    // -------------------------------------------------------------------------

    /*!
     *
     */
    virtual vector<IReader*> getReaders (
      void ) = 0;

    /*!
     *
     */
    virtual ECARD_PROTOCOL getProtocol (
      void ) = 0;
};

#endif
