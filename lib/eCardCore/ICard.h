// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: ICard.h 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file ICard.h
 */

#if !defined(__ICARD_INCLUDED__)
#define __ICARD_INCLUDED__

#include <eCardTypes.h>

#include "IReaderManager.h"

/*!
 * @class ICard
 */
class ICard
{
  private:
    ICard(
      const ICard&);

    ICard& operator=(
      const ICard&);

  protected:
    ECARD_HANDLE m_subSystem;
    unsigned short m_lastSW;
    UINT64 m_chipID;

  public:
    static const unsigned short MF = 0x3F00;

    /*!
     *
     */
    ICard (
      ECARD_HANDLE subSystem );

    /*!
     *
     */
    virtual ~ICard (
      void );

    /*!
     *
     */
    bool selectFile (
      unsigned short FID,
      const string& logMsg = "");

    /*!
     *
     */
    bool selectFile (
      const vector<BYTE>& longPath,
      const string& logMsg = "");

    /*!
     *
     */
    bool selectFile (
      const vector<BYTE>& longPath,
      vector<BYTE>& fci,
      const string& logMsg = "");

    /*!
     *
     */
    bool readRecord (
      BYTE record,
      vector<BYTE>& result);

    /*!
     *
     */
    bool readBinary (
      vector<BYTE>& result,
      const string& logMsg = "");

    /*!
     *
     */
    bool readBinary (
      vector<BYTE>& result,
      unsigned short size,
      const string& logMsg = "");

    /*!
     *
     */
    bool writeBinary (
      const vector<BYTE>& data,
      const string& logMsg = "");

    /*!
     *
     */
    bool generateRandom (
      BYTE size,
      vector<BYTE>& result);

    /*!
     *
     */
    bool verify(
      const string& pin,
      BYTE FID,
      PBYTE retryCount);

    /*!
     *
     */
    bool readRetryCount(
      BYTE FID,
      PBYTE retryCount);

    /*!
     *
     */
    CardResult sendAPDU(
      const CardCommand& cmd,
      const string& logMsg = "");

    /*!
     *
     */
    UINT64 getChipId(
      void);

    // -------------------------------------------------------------------------
    // Pure virtuals
    // -------------------------------------------------------------------------

    /*!
     *
     */
    virtual string getCardDescription (
      void ) = 0;

    /*!
     *
     */
    virtual ECARD_PIN_STATE getPinState (
      void ) = 0;    

    virtual bool selectEF(
      unsigned short FID) = 0;

    virtual bool selectDF(
      unsigned short FID) = 0;

    virtual bool selectEF(
      unsigned short FID,
      vector<BYTE>& fci) = 0;

}; // class ICard


#endif
