// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePACard.h 429 2009-09-18 09:19:55Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__EPACARD_INCLUDED__)
#define __EPACARD_INCLUDED__

// ---------------------------------------------------------------------------
// Global includes
// ---------------------------------------------------------------------------
#include <ICard.h>
#include <ICardDetector.h>

namespace Bundesdruckerei
{
  namespace nPA
  {

    /**
	*
	*/
	class ePACard : public ICard
    {
    public:
      /*!
       * ctor
       */
      ePACard(
        ECARD_HANDLE);

      /*!
       *
       */
      string getCardDescription (
        void );

      /*!
       *
       */
      ECARD_PIN_STATE getPinState (
        void );

      /*!
       * Select an file on the ePA.
       */
      bool selectEF(
        unsigned short FID);

      /*!
       * Select an EF on the ePA and return the FCP.
       */
      bool selectEF(
        unsigned short FID,       
        vector<BYTE>& fcp);

      /*!
       * Select an DF on the ePA.
       */
      bool selectDF(
        unsigned short FID);

      /*!
       * Select the MF of the ePA
       */
      bool selectMF(
        void);

      /*!
       * Return the allocated size for the file specified by FID.
       */
      unsigned short getFileSize(
        IN unsigned short FID);

      /*!
       *
       */
      bool readFile(
        unsigned short size,
        vector<BYTE>& result);

      /*
       *
       */
      bool sentAPDU(
        const CardCommand& cmd,
        vector<BYTE>& result);
    }; // class ePACard : public ICard
	
	
	/**
	*
	*/
	class ePACardDetector : public ICardDetector
	{
		public:
		/**
		*
		*/
		ICard* getCard (IReader* );
	}; // class ePACardDetector : public ICardDetector

  } // namespace nPA
} // namespace Bundesdruckerei

#endif 