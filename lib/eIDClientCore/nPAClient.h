/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPACLIENT_INCLUDED__)
#define __NPACLIENT_INCLUDED__

#include <map>
#include <list>
#include <string.h>

#include "eCardCore/CardCommand.h"
#include "eIDClientCore.h"
#include "eIDUtils.h"
#include "nPAClientProtocol.h"

using namespace Bundesdruckerei::eIDUtils;

struct CmpChar {
	bool operator()(const char *wc1, const char *wc2) const {
		return strcmp(wc1, wc2) < 0;
	}
};

typedef std::map<char *, char **, CmpChar> CharMap;
typedef std::map<char *, char **, CmpChar>::iterator CharMapIt;
typedef std::map<char *, char **, CmpChar>::const_iterator CharMapConstIt;

typedef std::list<std::string>  certificateList_t;

		typedef enum ProtocolState {
			Unauthenticated,
			PACE_Running,
			PACE_Done,
			TA_Running,
			TA_Done,
			CA_Running,
			Authenticated,
			Finished
		} Procolstate_t;

		/**
		 *
		 */
		class IClient
		{
		};

		/**
		 *
		 */
		class IIdP
		{
			public:
				/**
				 *
				 */
				IIdP(
					void) {
					/* Nop */
				}

				/**
				 *
				 */
				virtual ~IIdP(
					void) {
					/* Nop */
				}

				/**
				 *
				 */
				virtual bool open(
					void) = 0;

				/**
				 *
				 */
				virtual bool close(
					void) = 0;

				/**
				 *
				 */
				virtual NPACLIENT_ERROR initialize(
					IClient *pClient) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getTerminalCertificate(
					void) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getRequiredChat(
					void) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getOptionalChat(
					void) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getDVCACertificate(
					void) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getAuthenticatedAuxiliaryData(
					void) = 0;

				/**
				 *
				 */
				virtual std::vector<unsigned char> getCertificateDescription(
					void) = 0;

				/**
				 *
				 */
				virtual bool getTerminalAuthenticationData(
					const std::vector<unsigned char>& efCardAccess,
					const std::vector<unsigned char>& chat,
					const std::string &cvCACHAR,
					const std::vector<unsigned char>& idPICC,
					std::vector<std::vector<unsigned char> >& list_certificates,
					std::vector<unsigned char>& Puk_IFD_DH_CA) = 0;

				/**
				 *
				 */
				virtual bool createSignature(
					std::vector<unsigned char> toBeSigned,
					std::vector<unsigned char>& signature) = 0;

				/**
				 *
				 */
				virtual bool finalizeAuthentication(
					std::vector<unsigned char> efCardSecurity,
					std::vector<unsigned char> GAResult,
					std::vector<CAPDU>& apdus) = 0;

				/**
				 *
				 */
				virtual bool readAttributes(
					std::vector<RAPDU>& apdus) = 0;
		}; // class IIdP

		/**
		*
		*/
		class nPAClient : public IClient
		{
			private:
				IIdP               *m_Idp;
				IReaderManager     *m_hSystem;
				ICard              *m_hCard;
				ePAClientProtocol  *m_clientProtocol;
				static nPAClient   *m_instance;

				std::vector<unsigned char>  m_terminalRole;
				std::vector<unsigned char>  m_originalCHAT;
				std::vector<unsigned char>  m_requiredCHAT;
				std::vector<unsigned char>  m_optionalCHAT;
				Procolstate_t               m_protocolState;
				std::vector<unsigned char>  m_Puk_IFD_DH_CA;
				std::vector<unsigned char>  m_chatUsed;
				std::vector<CAPDU>  m_capdus;
				std::vector<RAPDU>  m_rapdus;

				nPAClient(
					void);

				nPAClient &operator=(
					const nPAClient &);

				/**
				 *
				 */
				nPAClient(
					IIdP *pIdP);

			public:
				static nPAClient *createInstance(
					IIdP *pIdP);

				/**
				 *
				 */
				~nPAClient(
					void);

				/**
				 *
				 */
				NPACLIENT_ERROR initialize(
					const CharMap *paraMap,
					ECARD_PROTOCOL usedProtocol);

				/*
				 *
				 */
				bool getCHAT(
					struct chat &chatFromCertificate);

				/*
				 *
				 */
				bool getRequiredCHAT(
					struct chat &requiredChat);

				/*
				 *
				 */
				bool getOptionalCHAT(
					struct chat &optionalChat);

				/*
				 *
				 */
				bool getValidFromDate(
					time_t &certificateValidFrom);

				/*
				 *
				 */
				bool getValidToDate(
					time_t &certificateValidTo);

				/*
				 *
				 */
				bool getCertificateDescription(
					enum DescriptionType &certificateDescriptionType,
					nPADataBuffer_t &certificateDescription);

				/*
				 *
				 */
				bool getCertificateDescriptionRaw(
					nPADataBuffer_t &certificateDescriptionRaw);

				/*
				 *
				 */
				bool getServiceName(
					nPADataBuffer_t &serviceName);

				/*
				 *
				 */
				bool getServiceURL(
					nPADataBuffer_t &serviceURL);

				bool passwordIsRequired(void) const;

				/*
				 *
				 */
				NPACLIENT_ERROR performPACE(
					const nPADataBuffer_t *const password,
					const struct chat *const chatSelectedByUser,
					const nPADataBuffer_t *const certificateDescription);

				/*
				 *
				 */
				NPACLIENT_ERROR performTerminalAuthentication(
					void);

				/*
				 *
				 */
				NPACLIENT_ERROR performChipAuthentication(
					void);

				/*
				 *
				 */
				NPACLIENT_ERROR readAttributed(void);
		}; // class nPAClient

#endif
