// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: PCSCReader.h 737 2010-03-23 14:24:31Z x_schrom $
// ---------------------------------------------------------------------------

#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_3_0
#else

#if !defined(__PCSCREDARE_INCLUDED__)
#define __PCSCREDARE_INCLUDED__

/*!
 * @file PCSCReader.h
 */

#include "IReader.h"
#include "ICardDetector.h"

#if defined(WIN32) || defined(WINCE)
#  include <winscard.h>
#else
#  include <PCSC/winscard.h>
#endif


/*!
 * @class PCSCReader
 */

class PCSCReader : public IReader
{
  private:
    SCARDHANDLE m_hCard;            // Handle to a card
#if !defined(__APPLE__)
    DWORD m_dwProtocol;             // Actual used protocol (T1/T0)
#else
    uint32_t m_dwProtocol;
#endif
    SCARDCONTEXT m_hScardContext;   // Handle to the PCSC subsystem

  public:
    /*!
     * @brief Constructor
     *
     * This function calls SCardEstablishContext to get a handle
     * to the PCSC subsystem. The handle is stored in m_hScardContext.
     */
    PCSCReader (
      const string&,
      vector<ICardDetector*>& );

    /*!
     * @brief Destructor
     *
     * This function calls SCardReleaseContext to free the handle
     * to the PCSC subsystem. The handle is stored in m_hScardContext.
     */
    ~PCSCReader (
      void );

    /*!
     * @brief Open a connection to a card.
     *
     * This function calls SCardConnectA to open a connection to a card.
     * The resulting handle ist stored in m_hCard.
     *
     * @return true if success. Otherwise false.
     */
    bool open (
      void );

    /*!
     * @brief Closing a card connection.
     *
     * This function calls SCardDisconnect to close the card connection.
     */
    void close (
      void );

    /*!
     * @brief Use this function to get a pointer to a ICard object.
     */
    ICard* getCard (
      void );

    /*!
     * @brief This command uses SCardTransmit to send a command to the card.
     */
    bool sendAPDU (
      UINT64 cardID,
      const CardCommand& cmd,
      CardResult& res,
      const string& logMsg);

    /*!
     *
     */
    vector<BYTE> getATRForPresentCard(
      void);
};

#endif
#endif // __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_3_0
