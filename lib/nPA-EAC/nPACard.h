/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPACARD_INCLUDED__)
#define __NPACARD_INCLUDED__

#include "eCardCore/ICard.h"
#include "eCardCore/ICardDetector.h"

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
                std::vector<unsigned char> m_ef_cardsecurity;
                std::vector<unsigned char> m_kEnc;
                std::vector<unsigned char> m_kMac;
                unsigned long long m_ssc;

            protected:
                CAPDU applySM(const CAPDU& apdu);
                RAPDU removeSM(const RAPDU& apdu);

            public:
                static const unsigned short FID_EF_CARDACCESS    = 0x011C;
                static const unsigned short FID_EF_CARDSECURITY  = 0x011D;
                static const unsigned char  SFID_EF_CARDACCESS   = 0x1C;
                static const unsigned char  SFID_EF_CARDSECURITY = 0x1D;

                /*!
                 * ctor
                 */
                ePACard(
                        IReader*);

                /*!
                 *
                 */
                string getCardDescription (
                        void );

                const vector<unsigned char> get_ef_cardaccess() const;
                const vector<unsigned char> get_ef_cardsecurity();

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
                        unsigned short FID);

                bool readFile(
                        unsigned char sfid,
                        size_t size,
                        vector<unsigned char>& result);

                bool readFile(
                        vector<unsigned char>& result);

                RAPDU sendAPDU(
                        const CAPDU& cmd);

                void setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac);

        };


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
