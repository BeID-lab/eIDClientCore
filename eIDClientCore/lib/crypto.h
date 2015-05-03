/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if defined(WIN32)
// CRYPTOPP includes
#include <cryptopp-5.6.0/sha.h>
#include <cryptopp-5.6.0/aes.h>
#include <cryptopp-5.6.0/modes.h>
#include <cryptopp-5.6.0/osrng.h>
#include <cryptopp-5.6.0/integer.h>
#include <cryptopp-5.6.0/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp-5.6.0/cmac.h>
#include <cryptopp-5.6.0/dh.h>
#else
// CRYPTOPP includes
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp/cmac.h>
#include <cryptopp/dh.h>
#endif

using CryptoPP::DH;
using CryptoPP::Integer;
using CryptoPP::CBC_Mode;
using CryptoPP::AES;
using CryptoPP::CMAC;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::ECP;
using CryptoPP::SHA1;
using CryptoPP::SHA224;
