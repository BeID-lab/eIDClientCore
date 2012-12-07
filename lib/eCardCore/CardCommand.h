/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__CARDCOMMAND_INCLUDED__)
#define __CARDCOMMAND_INCLUDED__

#include "eCardTypes.h"

#include <vector>

using namespace std;

class APDUException : public exception
{ };
class BufferTooLong : public APDUException
{
	private:
		size_t m_overrun_by;

	public:
		BufferTooLong(size_t overrun_by);

		const char *what() const throw();
};
class BufferTooSmall : public APDUException
{
	private:
		size_t m_underrun_by;

	public:
		BufferTooSmall(size_t underrun_by);

		const char *what() const throw();
};

class InconsistentData : public APDUException
{
	public:
		const char *what() const throw();
};

class WrongSM : public APDUException
{
	public:
		const char *what() const throw();
};


/*!
 * @class CAPDU
 */
class CAPDU
{
	private:
		unsigned char m_CLA;
		unsigned char m_INS;
		unsigned char m_P1;
		unsigned char m_P2;
		vector<unsigned char> m_data;
		size_t m_Ne;

		vector<unsigned char> encodeLength(size_t length, bool extendedOnThreeBytes) const;
		size_t decodeLength(const unsigned char *const len, bool isExtended, bool extendedOnThreeBytes) const;

	public:
		static const size_t        DATA_EXTENDED_MAX  = 0xFFFF + 1;
		static const size_t        DATA_SHORT_MAX     = 0xFF + 1;
		static const size_t        APDU_EXTENDED_MAX  = 4 + 3 + DATA_EXTENDED_MAX + 3;
		static const size_t        APDU_SHORT_MAX     = 4 + 1 + DATA_SHORT_MAX + 1;
		static const size_t        LENGTH_APDU_HEAD   = 4;

		static const unsigned char CLA_SM             = 0x0C;
		static const unsigned char CLA_CHAINING       = 0x10;

		CAPDU(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2);
		CAPDU(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2, vector<unsigned char> data);
		CAPDU(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2, vector<unsigned char> data, size_t ne);
		CAPDU(const vector<unsigned char> capdu);

		void appendData(unsigned char b);
		void appendData(const vector<unsigned char> data);

		bool isExtended(void) const;
		bool isSecure(void) const;
		bool isShort(void) const;
		void setData(const vector<unsigned char> data);
		void setCLA(unsigned char cla);
		void setP1(unsigned char p1);
		void setP2(unsigned char p2);
		void setNe(size_t Ne);
		unsigned char getCLA(void) const;
		unsigned char getINS(void) const;
		unsigned char getP1(void) const;
		unsigned char getP2(void) const;
		size_t getNe(void) const;
		const vector<unsigned char> getData(void) const;
		vector<unsigned char> encodedLc(void) const;
		vector<unsigned char> encodedLe(void) const;
		vector<unsigned char> asBuffer(void) const;
};

class SelectFile : public CAPDU
{
	public:
		static const unsigned char INS_SELECT        = 0xA4;
		static const unsigned char P1_SELECT_FID     = 0x00;
		static const unsigned char P1_SELECT_DF      = 0x01;
		static const unsigned char P1_SELECT_EF      = 0x02;
		static const unsigned char P1_SELECT_PARENT  = 0x03;
		static const unsigned char P1_SELECT_NAME    = 0x04;
		static const unsigned char P1_SELECT_MF_PATH = 0x08;
		static const unsigned char P1_SELECT_DF_PATH = 0x09;
		static const unsigned char P2_NO_RESPONSE    = 0x0C;
		static const unsigned char P2_FCP_TEMPLATE   = 0x04;

		SelectFile(unsigned char p1, unsigned char p2);
		SelectFile(unsigned char p1, unsigned char p2, unsigned short fid);
};

class DataUnitAPDU : public CAPDU
{
	public:
		static const unsigned char P1_SFID = 0x80;

		DataUnitAPDU(unsigned char ins, size_t offset, unsigned char sfid);
		DataUnitAPDU(unsigned char ins, size_t offset);
		DataUnitAPDU(unsigned char ins);
};

class ReadBinary : public DataUnitAPDU
{
	public:
		static const unsigned char INS_READ_BINARY = 0xB0;

		ReadBinary(size_t offset, unsigned char sfid);
		ReadBinary(size_t offset);
		ReadBinary(void);
};

class SecurityCAPDU : public CAPDU
{
	public:
		/** either the qualifier is known before issuing the command, or the
		 * command data field provides it */
		static const unsigned char P1_NO_INFO = 0x00;
		/** either the qualifier is known before issuing the command, or the
		 * command data field provides it */
		static const unsigned char P2_NO_INFO = 0x00;

		SecurityCAPDU(unsigned char ins, unsigned char p1, unsigned char p2);
};

class MSE : public SecurityCAPDU
{
	public:
		static const unsigned char INS_MSE             = 0x22;

		/** Secure messaging in command data field */
		static const unsigned char P1_SM_COMMAND_DATA  = 0x10;
		/** Secure messaging in response data field */
		static const unsigned char P1_SM_RESPONSE_DATA = 0x20;
		/** Computation, decipherment, internal authentication and key agreement */
		static const unsigned char P1_COMPUTE          = 0x40;
		/** Verification, encipherment, external authentication and key agreement */
		static const unsigned char P1_VERIFY           = 0x80;

		static const unsigned char P1_SET              = 0x01;
		static const unsigned char P1_STORE            = 0x02;
		static const unsigned char P1_RESTORE          = 0x03;
		static const unsigned char P1_ERASE            = 0x04;

		/** Control reference template for authentication (AT) */
		static const unsigned char P2_AT               = 0xA4;
		/** Control reference template for key agreement (KAT) */
		static const unsigned char P2_KAT              = 0xA6;
		/** Control reference template for hash-code (HT) */
		static const unsigned char P2_HT               = 0xAA;
		/** Control reference template for cryptographic checksum (CCT) */
		static const unsigned char P2_CCT              = 0xB4;
		/** Control reference template for digital signature (DST) */
		static const unsigned char P2_DST              = 0xB6;
		/** Control reference template for confidentiality (CT) */
		static const unsigned char P2_CT               = 0xB8;

		MSE(unsigned char p1, unsigned char p2);
};

class PSO : public CAPDU
{
	public:
		static const unsigned char INS_PSO             = 0x2A;

		/** Input template for the computation of a hash-code (the template is hashed) */
		static const unsigned char TAG_HASH = 0xA0;
		/** the verification of a cryptographic checksum (the template is integrated) */
		static const unsigned char TAG_VERIFY_CHECKSUM = 0xA2;
		/** the verification of a digital signature (the template is signed) */
		static const unsigned char TAG_VERIFY_SIGNATURE = 0xA8;
		/** the computation of a digital signature (the concatenated value fields are signed) */
		static const unsigned char TAG_COMPUTE_SIGNATURE_CAT = 0xAC;
		/** the computation of a certificate (the concatenated value fields are certified) */
		static const unsigned char TAG_COMPUTE_CERTIFICATE = 0xAE;
		/** the computation of a digital signature (the template is signed) */
		static const unsigned char TAG_COMPUTE_SIGNATURE = 0xBC;
		/** the verification of a certificate (the template is certified) */
		static const unsigned char TAG_VERIFY_CERTIFICATE = 0xBE;

		PSO(unsigned char p1, unsigned char p2);
};

class GeneralAuthenticate : public SecurityCAPDU
{
	public:
		static const unsigned char INS_GENERAL_AUTHENTICATE = 0x86;

		GeneralAuthenticate(unsigned char p1, unsigned char p2);
};

class GetChallenge : public SecurityCAPDU
{
	public:
		static const unsigned char INS_GET_CHALLENGE = 0x84;

		GetChallenge(unsigned char p1);
};

class ExternalAuthenticate : public SecurityCAPDU
{
	public:
		static const unsigned char INS_EXTERNAL_AUTHENTICATE = 0x82;

		ExternalAuthenticate(unsigned char p1, unsigned char p2);
};

class Verify : public SecurityCAPDU
{
	public:
		static const unsigned char INS_VERIFY = 0x20;

		Verify(unsigned char p1, unsigned char p2);
};

class RAPDU
{
	private:
		vector<unsigned char> m_data;
		unsigned char m_sw1;
		unsigned char m_sw2;

	public:
		static const size_t         DATA_EXTENDED_MAX  = 0xFFFF + 1;
		static const size_t         DATA_SHORT_MAX     = 0xFF + 1;
		static const size_t         RAPDU_EXTENDED_MAX = DATA_EXTENDED_MAX + 2;
		static const size_t         RAPDU_SHORT_MAX    = DATA_SHORT_MAX + 2;

		static const unsigned short ISO_SW_NORMAL      = 0x9000;

		RAPDU(const vector<unsigned char> rapdu);
		RAPDU(const vector<unsigned char> rdata, unsigned short sw);
		RAPDU(const vector<unsigned char> rdata, unsigned char sw1, unsigned char sw2);

		RAPDU(unsigned char sw1, unsigned char sw2);
		RAPDU(unsigned short sw);

		unsigned char getSW1(void) const;
		unsigned char getSW2(void) const;
		unsigned short getSW(void) const;
		const vector<unsigned char>& getData(void) const;
		vector<unsigned char> asBuffer(void) const;
		bool isOK(void) const;
};

#endif

