/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__PCSCREDARE_INCLUDED__)
#define __PCSCREDARE_INCLUDED__

#include "IReader.h"
#include "ICardDetector.h"

#include <winscard.h>

/*!
 * @class PCSCReader
 */

class PCSCReader : public IReader
{
  private:
    SCARDHANDLE m_hCard;            // Handle to a card
    DWORD m_dwProtocol;             // Actual used protocol (T1/T0)
    SCARDCONTEXT m_hScardContext;   // Handle to the PCSC subsystem
	DWORD m_ioctl_pace;

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
    vector<unsigned char> sendAPDU (
      const vector<unsigned char>& cmd);

    /*!
     *
     */
    vector<BYTE> getATRForPresentCard(
      void);

    bool supportsPACE(void) const;

	PaceOutput establishPACEChannel(const PaceInput&) const;
};

#endif
