/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#include "eCardCore/pace_reader.h"

#if defined(__APPLE__)
#include <string.h>
#include <stdint.h>
#else
#include <cstring>
#include <cstdint>
#endif //defined(__APPLE__)

#define PIN_ID_MRZ 0x01
#define PIN_ID_CAN 0x02
#define PIN_ID_PIN 0x03
#define PIN_ID_PUK 0x04

#define FUNCTION_EstabishPACEChannel        0x02
#define FUNCTION_GetReadersPACECapabilities 0x01

#define BITMAP_Qualified_Signature 0x10
#define BITMAP_German_eID          0x20
#define BITMAP_PACE                0x40
#define BITMAP_DestroyPACEChannel  0x80

std::vector<unsigned char> establishPACEChannel_getBuffer(const PaceInput &input)
{
	uint8_t length_CHAT, length_PIN, PinID;
	uint16_t lengthInputData, lengthCertificateDescription;

	if (input.get_chat().size() > 0xff || input.get_pin().size() > 0xff)
		throw PACEException();

	length_CHAT = (uint8_t) input.get_chat().size();
	length_PIN = (uint8_t) input.get_pin().size();
	/* FIXME */
#define REINERSCT_ACCEPTS_TESTDESCRIPTION 1
#if REINERSCT_ACCEPTS_TESTDESCRIPTION
	lengthCertificateDescription = (unsigned int) input.get_certificate_description().size();
#else
	lengthCertificateDescription = 0;
#endif
	lengthInputData = sizeof PinID
					  + sizeof length_CHAT + length_CHAT
					  + sizeof length_PIN + length_PIN
					  + sizeof lengthCertificateDescription + lengthCertificateDescription;
	size_t sendlen = 1 + 2 + lengthInputData;
	std::vector<unsigned char> sendbuf;
    sendbuf.resize(sendlen);

	switch (input.get_pin_id()) {
		case PaceInput::mrz:
			PinID = PIN_ID_MRZ;
			break;
		case PaceInput::pin:
			PinID = PIN_ID_PIN;
			break;
		case PaceInput::can:
			PinID = PIN_ID_CAN;
			break;
		case PaceInput::puk:
			PinID = PIN_ID_PUK;
			break;
		default:
			PinID = 0;
			break;
	}

	*DATA(sendbuf) = FUNCTION_EstabishPACEChannel;
	memcpy(DATA(sendbuf) + 1,
		   &lengthInputData, sizeof lengthInputData);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData,
		   &PinID, sizeof PinID);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID,
		   &length_CHAT, sizeof length_CHAT);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT,
		   DATA(input.get_chat()), length_CHAT);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT,
		   &length_PIN, sizeof length_PIN);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN,
		   DATA(input.get_pin()), length_PIN);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN + length_PIN,
		   &lengthCertificateDescription, sizeof lengthCertificateDescription);
	memcpy(DATA(sendbuf) + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN + length_PIN + sizeof lengthCertificateDescription,
		   DATA(input.get_certificate_description()), lengthCertificateDescription);

    return sendbuf;
}

PaceOutput establishPACEChannel_parseBuffer(unsigned char *output, size_t output_length)
{
	size_t parsed = 0;
	uint8_t lengthCAR, lengthCARprev;
	uint16_t lengthOutputData, lengthEF_CardAccess, length_IDicc, mse_setat;
	std::vector<unsigned char> CAR, CARprev, EF_CardAccess, IDicc;
	uint32_t result;
	PaceOutput paceoutput;

	/* Output Data */
	if (parsed + sizeof result > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&result, output + parsed, sizeof result);

	switch (result) {
		case 0x00000000:
			break;
		case 0xD0000001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Längen im Input sind inkonsistent");
			throw PACEException();
		case 0xD0000002:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Daten im Input");
			throw PACEException();
		case 0xD0000003:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Kombination von Daten im Input");
			throw PACEException();
		case 0xE0000001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Syntaxfehler im Aufbau der TLV-Antwortdaten");
			throw PACEException();
		case 0xE0000002:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete/fehlende Objekte in den TLV-Antwortdaten");
			throw PACEException();
		case 0xE0000003:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Der Kartenleser kennt die PIN-ID nicht.");
			throw PACEException();
		case 0xE0000006:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Fehlerhaftes PACE-Token");
			throw PACEException();
		case 0xE0000007:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Zertifikatskette für Terminalauthentisierung kann nicht gebildet werden");
			throw PACEException();
		case 0xE0000008:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Datenstruktur in Rückgabe der Chipauthentisierung");
			throw PACEException();
		case 0xE0000009:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Passive Authentisierung fehlgeschlagen");
			throw PACEException();
		case 0xE000000A:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Fehlerhaftes Chipauthentisierung-Token");
			throw PACEException();
		case 0xF0100001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Kommunikationsabbruch mit Karte.");
			throw PACEException();
		case 0xF0200001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Benutzerabbruch");
			throw PACEException();
		case 0xF0026283:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Die eID-PIN ist deaktiviert.");
			throw PACEException("0xF0026283");
		case 0xF0036982:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Die PIN wurde bereits zwei mal falsch eingegeben. CAN erforderlich");
			throw PACEException("0xF0036982");
		case 0xF00663C2:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Falsche PIN: Erster Fehlversuch");
			throw PACEException("0xF00663C2");
		case 0xF00663C1:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Falsche PIN: Zweiter Fehlversuch");
			throw PACEException("0xF00663C1");
		default:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Reader reported some error: %0X.", result);
			throw PACEException();
	}

	paceoutput.set_result(result);
	parsed += sizeof result;

	/* Output Data */
	if (parsed + sizeof lengthOutputData > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthOutputData, output + parsed, sizeof lengthOutputData);
	parsed += sizeof lengthOutputData;

	if (lengthOutputData != output_length - parsed) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	/* MSE:Set AT */
	if (parsed + sizeof mse_setat > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&mse_setat, output + parsed, sizeof mse_setat);
	paceoutput.set_status_mse_set_at(mse_setat);
	parsed += sizeof mse_setat;

	/* lengthEF_CardAccess */
	if (parsed + 2 > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthEF_CardAccess, output + parsed, sizeof lengthEF_CardAccess);
	parsed += sizeof lengthEF_CardAccess;

	/* EF.CardAccess */
	if (parsed + lengthEF_CardAccess > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	EF_CardAccess.assign(output + parsed, output + parsed + lengthEF_CardAccess);
	paceoutput.set_ef_cardaccess(EF_CardAccess);
	parsed += lengthEF_CardAccess;

	/* lengthCAR */
	if (parsed + sizeof lengthCAR > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthCAR, output + parsed, sizeof lengthCAR);
	parsed += sizeof lengthCAR;

	/* CAR */
	if (parsed + lengthCAR > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	CAR.assign(output + parsed, output + parsed + lengthCAR);
	paceoutput.set_car_curr(CAR);
	parsed += lengthCAR;

	/* lengthCARprev */
	if (parsed + sizeof lengthCARprev > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthCARprev, output + parsed, sizeof lengthCARprev);
	parsed += sizeof lengthCARprev;

	/* CARprev */
	if (parsed + lengthCARprev > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	CARprev.assign(output + parsed, output + parsed + lengthCARprev);
	paceoutput.set_car_prev(CARprev);
	parsed += lengthCARprev;

	/* lengthIDicc */
	if (parsed + sizeof length_IDicc > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&length_IDicc , output + parsed, sizeof length_IDicc);
	parsed += sizeof length_IDicc;

	/* IDicc */
	if (parsed + length_IDicc > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	IDicc.assign(output + parsed, output + parsed + length_IDicc);
	paceoutput.set_id_icc(IDicc);
	parsed += length_IDicc;

	if (parsed != output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Overrun by %d bytes", output_length - parsed);
		throw PACEException();
	}

	return paceoutput;
}

std::vector<unsigned char> getReadersPACECapabilities_getBuffer(void)
{
	unsigned char sendbuf[] = {
		FUNCTION_GetReadersPACECapabilities,
		0x00,              /* lengthInputData */
		0x00,              /* lengthInputData */
	};
    return std::vector<unsigned char> (sendbuf, sendbuf + sizeof sendbuf);
}

bool getReadersPACECapabilities_supportsPACE(unsigned char *output, size_t output_length)
{
    bool r = false;

    if (output_length == 7
            && output[0] == 0 && output[1] == 0
            && output[2] == 0 && output[3] == 0
            && output[6] & BITMAP_PACE) {
        eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports PACE");
        r = true;
    }

    return r;
}

bool getReadersPACECapabilities_supportsEID(unsigned char *output, size_t output_length)
{
    bool r = false;

    if (output_length == 7
            && output[0] == 0 && output[1] == 0
            && output[2] == 0 && output[3] == 0
            && output[6] & BITMAP_German_eID) {
        eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports German eID");
        r = true;
    }

    return r;
}

bool getReadersPACECapabilities_supportsSignature(unsigned char *output, size_t output_length)
{
    bool r = false;

    if (output_length == 7
            && output[0] == 0 && output[1] == 0
            && output[2] == 0 && output[3] == 0
            && output[6] & BITMAP_Qualified_Signature) {
        eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports qualified signature");
        r = true;
    }

    return r;
}

bool getReadersPACECapabilities_supportsDestroy(unsigned char *output, size_t output_length)
{
    bool r = false;

    if (output_length == 7
            && output[0] == 0 && output[1] == 0
            && output[2] == 0 && output[3] == 0
            && output[6] & BITMAP_DestroyPACEChannel) {
        eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports qualified signature");
        r = true;
    }

    return r;
}
