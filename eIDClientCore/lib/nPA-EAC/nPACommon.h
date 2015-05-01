/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPACOMMON_INCLUDED__)
#define __NPACOMMON_INCLUDED__

#include <vector>
#include <AlgorithmIdentifier.h>

#include "../crypto.h"

/**
 */
std::vector<unsigned char> calculateMAC(
	const std::vector<unsigned char>& toBeMaced,
	const std::vector<unsigned char>& kMac);

/**
 *
 */
std::vector<unsigned char> getCAR(
	const std::vector<unsigned char>& certificate);

/**
 *
 */
std::vector<unsigned char> getCHR(
	const std::vector<unsigned char>& certificate);

std::vector<unsigned char> generate_PrK_IFD_DHx(uint8_t standardizedDP);

std::vector<unsigned char> calculate_PuK_IFD_DH1(
	uint8_t standardizedDP,
	const std::vector<unsigned char>& PrK_IFD_DH1);

std::vector<unsigned char> calculate_SMKeys( std::vector<unsigned char> input, bool generateMac);

std::vector<unsigned char> generate_compressed_PuK(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char> &PuK_IFD_DH2);

ECP::Point vector2point(const std::vector<unsigned char> &v);
std::vector<unsigned char> point2vector(const ECP::Point &p, int curveLength);
std::vector<unsigned char> get_y(const std::vector<unsigned char> &v);
std::vector<unsigned char> get_x(const std::vector<unsigned char> &v);

std::vector<unsigned char> TLV_encode(unsigned int tag, const std::vector<unsigned char> &data);
std::vector<unsigned char> TLV_decode(const std::vector<unsigned char> &tlv,
	   	unsigned int *tag, std::vector<unsigned char> &data);

std::vector<unsigned char> calculate_KIFD_ICC(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH2,
	const std::vector<unsigned char>& PuK_ICC_DH2);
std::vector<unsigned char> calculate_ID_ICC(const std::vector<unsigned char>& PuK_ICC_DH2);

DH get_std_dp_0(void);

char*  my_itoa ( int value, char * str, int base );

#endif
