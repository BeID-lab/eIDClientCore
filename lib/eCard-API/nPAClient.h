// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: nPAClient.h 682 2010-02-15 14:09:14Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__NPACLIENT_INCLUDED__)
#define __NPACLIENT_INCLUDED__

#include <map>
#include <list>
#include <string.h>

#include "eCard-API/eIdUtils.h"
using namespace Bundesdruckerei::eIdUtils;

#include "eCard-API/eIdClientCoreLib.h"
#include "eCardCore/CardCommand.h"
#include "ePAClientProtocol.h"

struct CmpChar{
    bool operator()(const char* wc1, const char* wc2) const
    {
        return strcmp(wc1, wc2) < 0;
    }
};

typedef std::map<char *, char **, CmpChar> CharMap;
typedef std::map<char *, char **, CmpChar>::iterator CharMapIt;
typedef std::map<char *, char **, CmpChar>::const_iterator CharMapConstIt;

typedef std::list<std::string>	certificateList_t;

namespace Bundesdruckerei
{
  namespace nPA
  {
    typedef enum ProtocolState
    {
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
        void) { /* Nop */ }

      /**
       *
       */
      virtual ~IIdP(
        void) { /* Nop */ }

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
        const CharMap* paraMap,
        IClient* pClient) = 0;

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
        const std::string& cvCACHAR,
        const std::vector<unsigned char>& idPICC,
        std::vector<std::vector<unsigned char> >& list_certificates,
        std::vector<unsigned char>& x_Puk_IFD_DH_CA_,
        std::vector<unsigned char>& y_Puk_IFD_DH_CA_) = 0;

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
      IIdP*               m_Idp;
      IReaderManager*     m_hSystem;
      ICard*              m_hCard;
      ePAClientProtocol*  m_clientProtocol;
      static nPAClient*   m_instance;

      std::vector<unsigned char>  m_terminalRole;
      std::vector<unsigned char>  m_originalCHAT;
      std::vector<unsigned char>  m_requiredCHAT;
      std::vector<unsigned char>  m_optionalCHAT;
      Procolstate_t               m_protocolState;
      std::vector<unsigned char>  m_x_Puk_IFD_DH_CA_;
      std::vector<unsigned char>  m_y_Puk_IFD_DH_CA_;
      chat_t                      m_userSelectedChat;
      std::vector<unsigned char>  m_chatUsed;
      std::vector<CAPDU>  m_capdus;
      std::vector<RAPDU>  m_rapdus;

      nPAClient(
        void);

      nPAClient& operator=(
        const nPAClient&);

      /**
       *
       */
      nPAClient(
        IIdP* pIdP);

    public:
      static nPAClient* createInstance(
        IIdP* pIdP);

      /**
       *
       */
      ~nPAClient(
        void);

      /**
       *
       */
      NPACLIENT_ERROR initialize(
        const CharMap* paraMap,
        ECARD_PROTOCOL usedProtocol);

      /*
       *
       */
      bool getCHAT(
        chat_t &chatFromCertificate);

	  /*
       *
       */
      bool getCHAT2(
        nPADataBuffer_t &chatFromCertificate);

	  /*
       *
       */
      bool getRequiredCHAT(
        nPADataBuffer_t &requiredChat);

	  /*
       *
       */
      bool getOptionalCHAT(
        nPADataBuffer_t &optionalChat);

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
        nPADataBuffer_t &certificateDescription);

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

      /*
       *
       */
      NPACLIENT_ERROR performPACE(
        const char* password,
        chat_t chatSelectedByUser,
        nPADataBuffer_t &certificateDescription,
        unsigned char* retryCounter /*unused*/);

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
      NPACLIENT_ERROR readAttributed(
        nPADataBuffer_t &samlEncodedAttributes);
    }; // class nPAClient
  }
}

#endif