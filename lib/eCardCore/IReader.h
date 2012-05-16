// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: IReader.h 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file IReader.h
 */

#if !defined(__IREADER_INCLUDED__)
#define __IREADER_INCLUDED__

#include "CardCommand.h"
#include "ICardDetector.h"

#include <string>
using namespace std;

class ICard;

/*!
 * @class IReader
 *
 * @brief
 */

class IReader
{
  protected:
    string m_readerName;
    vector<ICardDetector*>& m_cardDetectors;

  private:
    IReader(
      void);

    IReader& operator=(
      const IReader&);

  public:
    /*!
     * @brief
     */
    IReader (
      const string& readerName,
      vector<ICardDetector*>& detector ) : m_readerName ( readerName ),
      m_cardDetectors ( detector ) {};

    /*!
     *
     */
    virtual ~IReader(
      void) {};

    /*!
     * @brief
     */
    string getReaderName (
      void )
    {
      return m_readerName;
    }

    // -------------------------------------------------------------------------
    // Pure virtuals
    // -------------------------------------------------------------------------

    /*!
     * @brief
     */
    virtual bool open (
      void ) = 0;

    /*!
     * @brief
     */
    virtual void close (
      void ) = 0;

    /*!
     * @brief
     */
    virtual ICard* getCard (
      void ) = 0;

    /*!
     * @brief
     */
    virtual bool sendAPDU (
      UINT64 cardID,
      const CardCommand& cmd,
      CardResult& res,
      const string& logMsg = "") = 0;

    /*!
     *
     */
    virtual vector<BYTE> getATRForPresentCard(
      void) = 0;
}; // class IReader

#endif // #if !defined(__IREADER_INCLUDED__)
