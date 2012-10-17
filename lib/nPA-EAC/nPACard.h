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

			public:
				static const unsigned short FID_EF_CARDACCESS    = 0x011C;
				static const unsigned short FID_EF_CARDSECURITY  = 0x011D;
				static const unsigned char  SFID_EF_CARDACCESS   = 0x1C;
				static const unsigned char  SFID_EF_CARDSECURITY = 0x1D;

				static const unsigned short FID_DG1   = 0x0101;
				static const unsigned short FID_DG2   = 0x0102;
				static const unsigned short FID_DG3   = 0x0103;
				static const unsigned short FID_DG4   = 0x0104;
				static const unsigned short FID_DG5   = 0x0105;
				static const unsigned short FID_DG6   = 0x0106;
				static const unsigned short FID_DG7   = 0x0107;
				static const unsigned short FID_DG8   = 0x0108;
				static const unsigned short FID_DG9   = 0x0109;
				static const unsigned short FID_DG10  = 0x010A;
				static const unsigned short FID_DG11  = 0x010B;
				static const unsigned short FID_DG12  = 0x010C;
				static const unsigned short FID_DG13  = 0x010D;
				static const unsigned short FID_DG14  = 0x010E;
				static const unsigned short FID_DG15  = 0x010F;
				static const unsigned short FID_DG16  = 0x0111;
				static const unsigned short FID_DG17  = 0x0112;
				static const unsigned short FID_DG18  = 0x0113;
				static const unsigned short FID_DG19  = 0x0114;
				static const unsigned short FID_DG20  = 0x0115;
				static const unsigned short FID_DG21  = 0x0116;

				static const unsigned char  SFID_DG1  = 0x01;
				static const unsigned char  SFID_DG2  = 0x02;
				static const unsigned char  SFID_DG3  = 0x03;
				static const unsigned char  SFID_DG4  = 0x04;
				static const unsigned char  SFID_DG5  = 0x05;
				static const unsigned char  SFID_DG6  = 0x06;
				static const unsigned char  SFID_DG7  = 0x07;
				static const unsigned char  SFID_DG8  = 0x08;
				static const unsigned char  SFID_DG9  = 0x09;
				static const unsigned char  SFID_DG10 = 0x0A;
				static const unsigned char  SFID_DG11 = 0x0B;
				static const unsigned char  SFID_DG12 = 0x0C;
				static const unsigned char  SFID_DG13 = 0x0D;
				static const unsigned char  SFID_DG14 = 0x0E;
				static const unsigned char  SFID_DG15 = 0x0F;
				static const unsigned char  SFID_DG16 = 0x10;
				static const unsigned char  SFID_DG17 = 0x11;
				static const unsigned char  SFID_DG18 = 0x12;
				static const unsigned char  SFID_DG19 = 0x13;
				static const unsigned char  SFID_DG20 = 0x14;
				static const unsigned char  SFID_DG21 = 0x15;

				ePACard(
					IReader *);

				ePACard(
					IReader *, const std::vector<unsigned char> ef_cardaccess);

				CAPDU applySM(const CAPDU &apdu);
				RAPDU removeSM(const RAPDU &apdu);

				/*!
				 *
				 */
				string getCardDescription(
					void);

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
					const CAPDU &cmd);

				void setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac);
                void setSSC(unsigned long long ssc);

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
				ICard *getCard(IReader *);
		}; // class ePACardDetector : public ICardDetector

	} // namespace nPA
} // namespace Bundesdruckerei

#endif
