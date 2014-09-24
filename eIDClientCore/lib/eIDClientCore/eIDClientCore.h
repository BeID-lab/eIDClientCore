/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPACLIENTLIB_INCLUDED__)
#define __NPACLIENTLIB_INCLUDED__

#include "nPA-EAC/nPAStatus.h"

typedef unsigned long NPACLIENT_ERROR;

#define NPACLIENT_ERROR_SUCCESS          0x00000000

#define NPACLIENT_INFO					 0x31000000
#define NPACLIENT_WARN					 0x32000000
#define NPACLIENT_ERRO					 0x33000000

#define NPACLIENT_ERROR_IDP_INITIALIZATION_ERROR		NPACLIENT_ERRO + 0x00000001
#define NPACLIENT_ERROR_IDP_INSTANTIATION_ERROR			NPACLIENT_ERRO + 0x00000002
#define NPACLIENT_ERROR_IDP_INVALID_CONNECTION			NPACLIENT_ERRO + 0x00000003
#define NPACLIENT_ERROR_IDP_OPENSESSION_ERROR			NPACLIENT_ERRO + 0x00000004
#define NPACLIENT_ERROR_IDP_OPENSESSION_INV_RESPONSE	NPACLIENT_ERRO + 0x00000005
#define NPACLIENT_ERROR_INVALID_PROTOCOL_STATE			NPACLIENT_ERRO + 0x00000006
#define NPACLIENT_ERROR_GUI_ABORT						NPACLIENT_ERRO + 0x00000007

#define NPACLIENT_ERROR_GENERAL_INITIALIZATION_FAILURE  NPACLIENT_ERRO + 0x00000010

#define NPACLIENT_ERROR_CLIENT_INSTANTIATION_ERROR		NPACLIENT_ERRO + 0x00000050
#define NPACLIENT_ERROR_CLIENT_INITIALIZATION_ERROR		NPACLIENT_ERRO + 0x00000051
#define NPACLIENT_ERROR_CLIENT_CONNECTION_ERROR			NPACLIENT_ERRO + 0x00000052
#define NPACLIENT_ERROR_CREATE_THREAD					NPACLIENT_ERRO + 0x00000053

#define NPACLIENT_ERROR_READ_CHAT						NPACLIENT_ERRO + 0x00000070
#define NPACLIENT_ERROR_READ_VALID_FROM_DATE			NPACLIENT_ERRO + 0x00000071
#define NPACLIENT_ERROR_READ_VALID_TO_DATE				NPACLIENT_ERRO + 0x00000072
#define NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION	NPACLIENT_ERRO + 0x00000073
#define NPACLIENT_ERROR_READ_SERVICE_NAME				NPACLIENT_ERRO + 0x00000074
#define NPACLIENT_ERROR_READ_SERVICE_URL				NPACLIENT_ERRO + 0x00000075

#define NPACLIENT_ERROR_PCSC_INITIALIZATION_FAILED		NPACLIENT_ERRO + 0x00000080
#define NPACLIENT_ERROR_INVALID_CARD_DETECTOR			NPACLIENT_ERRO + 0x00000081
#define NPACLIENT_ERROR_NO_USABLE_READER_PRESENT		NPACLIENT_ERRO + 0x00000082
#define NPACLIENT_ERROR_TO_MANY_CARDS_FOUND				NPACLIENT_ERRO + 0x00000083
#define NPACLIENT_ERROR_NO_VALID_CARD_FOUND				NPACLIENT_ERRO + 0x00000084
#define NPACLIENT_ERROR_PROTCOL_INITIALIZATION_FAILD	NPACLIENT_ERRO + 0x00000085
#define NPACLIENT_ERROR_PACE_FAILED						NPACLIENT_ERRO + 0x00000086
#define NPACLIENT_ERROR_TA_INITIALIZATION_FAILD			NPACLIENT_ERRO + 0x00000087
#define NPACLIENT_ERROR_TA_FAILED						NPACLIENT_ERRO + 0x00000088
#define NPACLIENT_ERROR_CREATE_SIGNATURE_ERROR			NPACLIENT_ERRO + 0x00000089
#define NPACLIENT_ERROR_SEND_SIGNATURE_ERROR			NPACLIENT_ERRO + 0x00000090
#define NPACLIENT_ERROR_CA_FAILED						NPACLIENT_ERRO + 0x00000091
#define NPACLIENT_ERROR_CA_SERVER_FAILED				NPACLIENT_ERRO + 0x00000092

#define NPACLIENT_ERROR_INVALID_PARAMETER1				NPACLIENT_ERRO + 0x00000100
#define NPACLIENT_ERROR_INVALID_PARAMETER2				NPACLIENT_ERRO + 0x00000101
#define NPACLIENT_ERROR_INVALID_PARAMETER3				NPACLIENT_ERRO + 0x00000102
#define NPACLIENT_ERROR_INVALID_PARAMETER4				NPACLIENT_ERRO + 0x00000103
#define NPACLIENT_ERROR_INVALID_PARAMETER5				NPACLIENT_ERRO + 0x00000104
#define NPACLIENT_ERROR_INVALID_PARAMETER6				NPACLIENT_ERRO + 0x00000105
#define NPACLIENT_ERROR_INVALID_PARAMETER7				NPACLIENT_ERRO + 0x00000106
#define NPACLIENT_ERROR_INVALID_PARAMETER8				NPACLIENT_ERRO + 0x00000107
#define NPACLIENT_ERROR_INVALID_PARAMETER9				NPACLIENT_ERRO + 0x00000108

#define NPACLIENT_ERROR_READ_FAILED						NPACLIENT_ERRO + 0x00000200
#define NPACLIENT_ERROR_READ_INVALID_RETURN_VALUE		NPACLIENT_ERRO + 0x00000201

#define NPACLIENT_ERROR_TRANSMISSION_ERROR				NPACLIENT_ERRO + 0x00000300
#define NPACLIENT_ERROR_NO_TERMINAL_CERTIFICATE			NPACLIENT_ERRO + 0x00000301
#define NPACLIENT_ERROR_NO_CERTIFICATE_DESCRIPTION		NPACLIENT_ERRO + 0x00000302

#define NPACLIENT_ERROR_UNKNOWN_READER_TYPE				NPACLIENT_ERRO + 0x00000400

#define NPACLIENT_ERROR_PAOS							NPACLIENT_ERRO + 0x00000500

#define NPACLIENT_ERROR_ASN1_ENCODE						NPACLIENT_ERRO + 0x00000600
#define NPACLIENT_ERROR_ASN1_DECODE						NPACLIENT_ERRO + 0x00000601

#define NPACLIENT_ERROR_TRANSACTION_HASH_NOT_VALID		NPACLIENT_ERRO + 0x00000700

#define NPACLIENT_ERROR_GUI_PIN_TOO_LONG				NPACLIENT_ERRO + 0x00000800

typedef unsigned long NPACLIENT_STATE;

#define NPACLIENT_STATE_INITIALIZE        (NPACLIENT_STATE) 0x00000001
#define NPACLIENT_STATE_GOT_PACE_INFO     (NPACLIENT_STATE) 0x00000002
#define NPACLIENT_STATE_PACE_PERFORMED    (NPACLIENT_STATE) 0x00000003
#define NPACLIENT_STATE_TA_PERFORMED      (NPACLIENT_STATE) 0x00000004
#define NPACLIENT_STATE_CA_PERFORMED      (NPACLIENT_STATE) 0x00000005
#define NPACLIENT_STATE_READ_ATTRIBUTES   (NPACLIENT_STATE) 0x00000006

#define MAX_PIN_SIZE 0xff

/**
 *
 */
typedef struct AuthenticationParams {
	const char *m_serverAddress;
	const char *m_transactionURL;
	const char *m_sessionIdentifier;
	const char *m_binding;
	const char *m_pathSecurityProtocol;
	const char *m_pathSecurityParameters;
	const char *m_refreshAddress;
	const char *m_pin;
	const char *m_userSelectedChat;
	const char *m_userSelectedCardReader;
	void       *m_extension; 

	/**
	 *
	 */
//	AuthenticationParams(
//		void) : m_serverAddress(0x00), m_sessionIdentifier(0x00), m_binding(0x00),
//		m_pathSecurityProtocol(0x00), m_pathSecurityParameters(0x00), m_refreshAddress(0x00),
//		m_pin(0), m_userSelectedChat(0x00), m_extension(0x00) {
//		/* */
//	}
} AuthenticationParams_t;

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(WIN32) || defined(WINCE)// Windows related stuff
#   if defined(ECARD_EXPORTS)
#       define ECARD_API __declspec(dllexport)
#   else
#       define ECARD_API __declspec(dllimport)
#   endif
#   define __STDCALL__ __stdcall
#else // Linux related stuff
#   define ECARD_API
#   define __STDCALL__
#endif

#include <time.h>

typedef void *EIDCLIENT_CARD_READER_HANDLE;
typedef EIDCLIENT_CARD_READER_HANDLE *P_EIDCLIENT_CARD_READER_HANDLE;
   
typedef void *EIDCLIENT_CONNECTION_HANDLE;
typedef EIDCLIENT_CONNECTION_HANDLE *P_EIDCLIENT_CONNECTION_HANDLE;

/*!
 * @enum ECARD_READER
 */
	enum ECARD_READER {
		READER_PCSC,
		READER_TCP,
		READER_EXTERNAL,
	};

	typedef void (*nPAeIdProtocolStateCallback_t)(
		const NPACLIENT_STATE state,
		const NPACLIENT_ERROR error);

	enum DescriptionType {
		DT_UNDEF = 0,
		DT_PLAIN = 1,
		DT_HTML  = 2,
		DT_PDF   = 3,
	};

	enum PinID {
		PI_UNDEF,
		PI_MRZ,
		PI_CAN,
		PI_PIN,
		PI_PUK,
	};

	enum TerminalType {
		TT_AT,
		TT_IS,
		TT_ST,
		TT_invalid,
	};

	struct chat {
		enum TerminalType type;
		union {
			struct {
				char age_verification;
				char community_id_verification;
				char restricted_id;
				char privileged;
				char can_allowed;
				char pin_management;
				char install_cert;
				char install_qualified_cert;
				char read_dg1;
				char read_dg2;
				char read_dg3;
				char read_dg4;
				char read_dg5;
				char read_dg6;
				char read_dg7;
				char read_dg8;
				char read_dg9;
				char read_dg10;
				char read_dg11;
				char read_dg12;
				char read_dg13;
				char read_dg14;
				char read_dg15;
				char read_dg16;
				char read_dg17;
				char read_dg18;
				char read_dg19;
				char read_dg20;
				char read_dg21;
				char write_dg17;
				char write_dg18;
				char write_dg19;
				char write_dg20;
				char write_dg21;
				char RFU1;
				char RFU2;
				char RFU3;
				char RFU4;
				char role;
			} at;
			struct {
				char read_finger;
				char read_iris;
				char RFU1;
				char RFU2;
				char RFU3;
				char read_eid;
				char role;
			} is;
			struct {
				char generate_signature;
				char generate_qualified_signature;
				char RFU1;
				char RFU2;
				char RFU3;
				char RFU4;
				char role;
			} st;
		} authorization;
	};

	typedef struct {
		unsigned char *pDataBuffer;
		unsigned long bufferSize;
	} nPADataBuffer_t;

	typedef struct {
		const enum DescriptionType description_type;
		const nPADataBuffer_t description;
		const nPADataBuffer_t name;
		const nPADataBuffer_t url;
		const struct chat chat_required;
		const struct chat chat_optional;
		const time_t valid_from;
		const time_t valid_to;
		const nPADataBuffer_t transactionInfo;
		const nPADataBuffer_t transactionInfoHidden;
	} SPDescription_t;

	typedef struct {
		const char pin_required;
		const enum PinID pin_id;

		/** The CHAT selected by the user. To be filled by the application.
		 *
		 *  \c chat_selected is initialized with data from \c chat_required */
		struct chat chat_selected;
		/** The actual secret (PIN/PUK/CAN/MRZ). To be filled by the application.
		 *
		 *  The buffer is already allocated with \c MAX_PIN_SIZE bytes
		 *  (although pin.bufferSize will be initialized with \c 0). The
		 *  application shall copy the secret and set pin.bufferSize
		 *  appropriately. If pin_required is set because of an PACE-enabled
		 *  reader the application may not pass a secret to eIDClientCore */
		nPADataBuffer_t pin;
	} UserInput_t;

	typedef NPACLIENT_ERROR(*nPAeIdUserInteractionCallback_t)
	(const SPDescription_t *description, UserInput_t *input);


	NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocol(
		const enum ECARD_READER reader,
		const char *const IdpAddress,
		const char *const SessionIdentifier,
		const char *const PathSecurityParameters,
		const char *const CardReaderName,
        const char *const TransactionURL,
		const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
		const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);
    
	typedef NPACLIENT_ERROR(*nPAeIdPerformAuthenticationProtocol_t)(
		const enum ECARD_READER reader,
        const char *const IdpAddress,
        const char *const SessionIdentifier,
        const char *const PathSecurityParameters,
        const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
        const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);    

	bool validateTransactionData(unsigned char* transaction_data,
								 int transaction_data_length,
								 unsigned char* transaction_hash,
								 int transaction_hash_length);

// ASN.1 helper
    bool getCertificateInformation( const nPADataBuffer_t certificateDescriptionRaw,
                                   enum DescriptionType *certificateDescriptionType,
                                   nPADataBuffer_t *certificateDescription,
                                   nPADataBuffer_t *serviceName,
                                   nPADataBuffer_t *serviceURL);
    
    bool getCertificateValidDates( const nPADataBuffer_t certificate,
                                  time_t *certificateValidFrom,
                                  time_t *certificateValidTo);

    bool getChatInformation(const nPADataBuffer_t requCHAT,
                            const nPADataBuffer_t optCHAT,
                            struct chat *requiredChat,
                            struct chat *optionalChat);
    
#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__NPACLIENTLIB_INCLUDED__)
