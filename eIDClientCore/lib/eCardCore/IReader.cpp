/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "IReader.h"
#include "debug.h"
#include "nPA-EAC/nPAAPI.h"

#ifdef _WIN32
typedef char uint8_t;
#endif

bool IReader::supportsPACEboxed(void)
{
    uint8_t getReaderPACECapabilites[] = {0xFF, 0x9A, 0x04, 0x01};

    if (m_boxing_support == untested) {
        std::vector<unsigned char> result = transceive(
                std::vector<unsigned char> (getReaderPACECapabilites,
                    getReaderPACECapabilites + sizeof getReaderPACECapabilites));
        if (result.size() > 2
                && result[result.size()-2] == 0x90
                && result[result.size()-1] == 0x00) {
            m_boxing_support = tested_yes;
        } else {
            m_boxing_support = tested_no;
        }
    }

    return m_boxing_support == tested_yes;
}

PaceOutput IReader::establishPACEChannelBoxed(const PaceInput &pace_input)
{
    PaceOutput pace_output;
    unsigned char *establishPACEChannelInput_data = NULL;
    size_t establishPACEChannelInput_data_len = 0;


	//TODO: support for other Hash algorithms
	unsigned char* oid_hash_transactiondata = (unsigned char*) "\x60\x86\x48\x01\x65\x03\x04\x02\x04"; //sha224
	size_t oid_hash_transactiondata_length = 9;

    ECARD_STATUS r = encode_EstablishPACEChannelInput(pace_input.get_pin_id(),
            DATA(pace_input.get_pin()), pace_input.get_pin().size(),
            DATA(pace_input.get_chat()), pace_input.get_chat().size(),
            DATA(pace_input.get_chat_required()), pace_input.get_chat_required().size(),
            DATA(pace_input.get_chat_optional()), pace_input.get_chat_optional().size(),
            DATA(pace_input.get_certificate_description()), pace_input.get_certificate_description().size(),
            DATA(pace_input.get_transaction_info_hidden()), pace_input.get_transaction_info_hidden().size(),
			oid_hash_transactiondata, oid_hash_transactiondata_length,
            &establishPACEChannelInput_data, &establishPACEChannelInput_data_len);
    if (ECARD_SUCCESS != r)
        return pace_output;

    /* construct case 4 extended length APDU */
    uint8_t establishPACEChannel_header[] = {0xFF, 0x9A, 0x04, 0x02};
    /* CLA INS P1 P2 */
    std::vector<unsigned char> establishPACEChannel(establishPACEChannel_header,
            establishPACEChannel_header + sizeof establishPACEChannel_header);
    /* Lc (extended length) */
    establishPACEChannel.push_back(0x00);
    establishPACEChannel.push_back(establishPACEChannelInput_data_len / 256);
    establishPACEChannel.push_back(establishPACEChannelInput_data_len % 256);
    establishPACEChannel.insert(establishPACEChannel.end(),
            establishPACEChannelInput_data,
            establishPACEChannelInput_data + establishPACEChannelInput_data_len);
    free(establishPACEChannelInput_data);
    /* Le (extended length) */
    establishPACEChannel.push_back(0x00);
    establishPACEChannel.push_back(0x00);
    /* FIXME the reader may send data that is too long for the reader to
     * handle. should use something like this.max_receive_size */

	hexdump(DEBUG_LEVEL_APDU,"ASN1 input data",DATA(establishPACEChannel),establishPACEChannel.size());

    std::vector<unsigned char> establishPACEChannelOutput =
        transceive(establishPACEChannel);

	hexdump(DEBUG_LEVEL_APDU,"ASN1 output data",DATA(establishPACEChannelOutput),establishPACEChannelOutput.size());

	unsigned int pace_result = 0;
    unsigned short status_mse_set_at = 0;
    unsigned char *ef_cardaccess_buf = NULL;
    size_t ef_cardaccess_len = 0;
    unsigned char *car_curr = NULL;
    size_t car_curr_len = 0;
    unsigned char *car_prev = NULL;
    size_t car_prev_len = 0;
    unsigned char *id_icc = NULL;
    size_t id_icc_len = 0;
    unsigned char *chat_used_buf = NULL;
    size_t chat_len = 0;
    size_t chat_used_len = 0;
    r = decode_EstablishPACEChannelOutput(DATA(establishPACEChannelOutput),
            establishPACEChannelOutput.size(), &pace_result,
            &status_mse_set_at, &ef_cardaccess_buf,
            &ef_cardaccess_len, &car_curr,
            &car_curr_len,
            &car_prev, &car_prev_len,
            &id_icc, &id_icc_len, &chat_used_buf, &chat_used_len);
    if (ECARD_SUCCESS != r)
        return pace_output;

    if (car_curr && car_curr_len) {
        pace_output.set_car_curr(std::vector<unsigned char>
                (car_curr, car_curr + car_curr_len));
        free(car_curr);
    }
    if (car_prev && car_prev_len) {
        pace_output.set_car_prev(std::vector<unsigned char>
                (car_prev, car_prev + car_prev_len));
        free(car_prev);
    }
    if (ef_cardaccess_buf && ef_cardaccess_len) {
        pace_output.set_ef_cardaccess(std::vector<unsigned char>
                (ef_cardaccess_buf, ef_cardaccess_buf + ef_cardaccess_len));
        free(ef_cardaccess_buf);
    }
    if (id_icc && id_icc_len) {
        pace_output.set_id_icc(std::vector<unsigned char>
                (id_icc, id_icc + id_icc_len));
        free(id_icc);
    }
    if (chat_used_buf && chat_used_len) {
        pace_output.set_chat(std::vector<unsigned char>
                (chat_used_buf, chat_used_buf + chat_used_len));
        free(chat_used_buf);
    } else {
        pace_output.set_chat(pace_input.get_chat());
    }
    pace_output.set_result(pace_result);

    return pace_output;
}

PaceOutput IReader::establishPACEChannel(const PaceInput &pace_input)
{
    PaceOutput pace_output;
    if (supportsPACEboxed()) {
        pace_output = establishPACEChannelBoxed(pace_input);
    } else if (supportsPACEnative()) {
        pace_output = establishPACEChannelNative(pace_input);
    }
    return pace_output;
}

bool IReader::supportsPACE(void)
{
    return supportsPACEnative() || supportsPACEboxed();
}

PaceOutput IReader::establishPACEChannelNative(const PaceInput &pace_input)
{
    return PaceOutput();
}
