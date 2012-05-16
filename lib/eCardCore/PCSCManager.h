// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: PCSCManager.h 771 2010-06-11 11:08:46Z x_schrom $
// ---------------------------------------------------------------------------

/*!
 * @file PCSCManager.h
 */

#if !defined(__PCSCMANAGER_INCLUDED__)
#define __PCSCMANAGER_INCLUDED__

#if !defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_3_0

#include "IReaderManager.h"

#if defined(WIN32) || defined(WINCE)
#  include <winscard.h>
#else
#  include <PCSC/winscard.h>
#endif

/*!
 * @class PCSCManager
 */
class PCSCManager : public IReaderManager
{
  private:
    /*!
     *
     */
    void findReaders (
      void );

  public:
    /*!
     *
     */
    PCSCManager (
      void );    

    /*!
     *
     */
    ~PCSCManager (
      void );

    /*!
     *
     */
    vector<IReader*> getReaders (
      void );

    /*!
     *
     */
    ECARD_PROTOCOL getProtocol()
    {
      return PROTOCOL_PCSC;
    };
};

#endif // __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_3_0
#endif