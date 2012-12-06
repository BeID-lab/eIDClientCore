/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPACOMMON_INCLUDED__)
#define __NPACOMMON_INCLUDED__

#include <vector>
#include <AlgorithmIdentifier.h>

#if defined(WIN32)
// CRYPTOPP includes
#include <cryptopp-5.6.0/sha.h>
#include <cryptopp-5.6.0/aes.h>
#include <cryptopp-5.6.0/modes.h>
#include <cryptopp-5.6.0/osrng.h>
#include <cryptopp-5.6.0/integer.h>
#include <cryptopp-5.6.0/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp-5.6.0/cmac.h>
#else
// CRYPTOPP includes
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp/cmac.h>
#endif

USING_NAMESPACE(CryptoPP)

/**
 */
std::vector<unsigned char> calculateMAC(
	const std::vector<unsigned char>& toBeMaced,
	const std::vector<unsigned char>& kMac);

/**
 *
 */
std::string getCAR(
	const std::vector<unsigned char>& certificate);

/**
 *
 */
std::string getCHR(
	const std::vector<unsigned char>& certificate);

std::vector<unsigned char> generate_PrK_IFD_DHx(const OBJECT_IDENTIFIER_t &OID_);

std::vector<unsigned char> calculate_PuK_IFD_DH1(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH1);

std::vector<unsigned char> calculate_SMKeys( std::vector<unsigned char> input, bool generateMac);

std::vector<unsigned char> generate_compressed_PuK(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char> &PuK_IFD_DH2);

ECP::Point vector2point(const std::vector<unsigned char> &v);
std::vector<unsigned char> point2vector(const ECP::Point &p);
std::vector<unsigned char> get_y(const std::vector<unsigned char> &v);
std::vector<unsigned char> get_x(const std::vector<unsigned char> &v);

std::vector<unsigned char> TLV_encode(unsigned int tag, const std::vector<unsigned char> &data);
std::vector<unsigned char> TLV_decode(const std::vector<unsigned char> &tlv,
	   	unsigned int *tag, std::vector<unsigned char> &data);

std::vector<unsigned char> calculate_KIFD_ICC(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH2,
	const std::vector<unsigned char>& PuK_ICC_DH2);
std::vector<unsigned char> calculate_ID_ICC(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PuK_ICC_DH2);
#endif
