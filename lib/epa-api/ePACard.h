// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePACard.h 429 2009-09-18 09:19:55Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__EPACARD_INCLUDED__)
#define __EPACARD_INCLUDED__

#include "ICard.h"
#include "ICardDetector.h"

namespace Bundesdruckerei
{
    namespace nPA
    {

        /**
         *
         */
        class ePACard : public ICard
        {
            private:
                std::vector<unsigned char> m_ef_cardaccess;
                std::vector<unsigned char> m_kEnc;
                std::vector<unsigned char> m_kMac;
                unsigned long long m_ssc;

            protected:
                CAPDU applySM(const CAPDU& apdu);
                RAPDU removeSM(const RAPDU& apdu);

            public:
                static const unsigned short FID_EF_CARDACCESS = 0x011C;
                static const unsigned char SFID_EF_CARDACCESS =   0x1C;

                bool subSystemSupportsPACE(void);
                PaceOutput subSystemEstablishPACEChannel(const PaceInput& input);

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
                 * Select an EF on the ePA.
                 */
                bool selectEF(
                        unsigned short FID);

                /*!
                 * Select an EF on the ePA and return the FCP.
                 */
                bool selectEF(
                        unsigned short FID,
                        vector<unsigned char>& fcp);

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
                        size_t size,
                        vector<unsigned char>& result);

                bool readFile(
                        unsigned char sfid,
                        size_t size,
                        vector<unsigned char>& result);

                RAPDU sendAPDU(
                        const CAPDU& cmd);

                void setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac);

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
