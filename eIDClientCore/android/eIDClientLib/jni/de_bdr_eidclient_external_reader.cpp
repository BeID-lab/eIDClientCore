/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#include <jni.h>
#include "eCardCore/eIdClientCardReader.h"
#include "eCardCore/pace_reader.h"
#include "eIDClientCore/eIDClientCore.h"
#include "nPA-EAC/nPAAPI.h"
#include <android/log.h>
#include <stdlib.h>

#define LOG_TAG "eidclient_jni"
#define ALOG(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ext_reader_android_ctx {
	JNIEnv *env;
	jobject reader;
	jclass reader_cla;
	//methods
	jmethodID powerOn;
	jmethodID powerOff;
	jmethodID getATR;
	jmethodID processAPDU;
	jmethodID supportsPACE;
} ANDROID_READER_CTX;

extern JNIEnv *EID_env;
extern jobject EID_reader;

static ANDROID_READER_CTX* create_reader_contex() {

	ANDROID_READER_CTX *c = (ANDROID_READER_CTX *) malloc(
			sizeof(ANDROID_READER_CTX));

	if (c && EID_env && EID_reader) {
		c->env = EID_env;
		c->reader = EID_reader;
		c->reader_cla = c->env->FindClass("de/bdr/eidclient/Reader");
		c->powerOff = c->env->GetMethodID(c->reader_cla, "powerOff", "()V");
		c->powerOn = c->env->GetMethodID(c->reader_cla, "powerOn", "()Z");
		c->getATR = c->env->GetMethodID(c->reader_cla, "getATR", "()[B");
		c->processAPDU = c->env->GetMethodID(c->reader_cla, "processAPDU",
				"([B)[B");
		c->supportsPACE = c->env->GetMethodID(c->reader_cla, "supportsPACE",
				"()Z");

		EID_reader = NULL;
	}

	return c;
}

ECARD_STATUS CardReaderOpen(P_EIDCLIENT_CARD_READER_HANDLE hCardReader,
		const char* const readerName) {

	ALOG("Entered CardReaderOpen");

	ANDROID_READER_CTX *ctx = create_reader_contex();

	if (ctx) {
		jboolean suc = ctx->env->CallBooleanMethod(ctx->reader, ctx->powerOn);

		if (!suc) {
			free(ctx);
			return ECARD_ERROR;
		}

		*hCardReader = (EIDCLIENT_CARD_READER_HANDLE) ctx;

		return ECARD_SUCCESS;
	}

	return ECARD_ERROR;
}

ECARD_STATUS CardReaderClose(EIDCLIENT_CARD_READER_HANDLE hCardReader) {

	ALOG("Entered CardReaderClose");

	ANDROID_READER_CTX *ctx = (ANDROID_READER_CTX *) hCardReader;

	if (ctx) {
		ctx->env->CallVoidMethod(ctx->reader, ctx->powerOff);

		free(hCardReader);

		return ECARD_SUCCESS;
	}

	return ECARD_ERROR;
}

ECARD_STATUS CardReaderSend(EIDCLIENT_CARD_READER_HANDLE hCardReader,
		const unsigned char* const cardCommand,
		const unsigned long nLengthCardCommand, unsigned char* const result,
		unsigned long* const nLengthResult) {

	ALOG("Entered CardReaderSend");

	ECARD_STATUS r = ECARD_ERROR;
	unsigned long nlen = *nLengthResult;
	unsigned long len;
	jbyteArray cmd_j;

	jbyteArray rsp_j;
	jbyte* rsp;

	ANDROID_READER_CTX *ctx = (ANDROID_READER_CTX *) hCardReader;

	if (ctx) {

		cmd_j = ctx->env->NewByteArray(nLengthCardCommand);

		if (cmd_j) {
			ctx->env->SetByteArrayRegion(cmd_j, 0, nLengthCardCommand,
					(jbyte *) cardCommand);

			rsp_j = (jbyteArray) ctx->env->CallObjectMethod(ctx->reader,
					ctx->processAPDU, cmd_j);

			if(rsp_j)
				len = (unsigned long) ctx->env->GetArrayLength(rsp_j);
			else
				len = nlen + 1;

			if (len <= nlen) {
				rsp = ctx->env->GetByteArrayElements(rsp_j, NULL);
				memcpy(result, rsp, len);
				*nLengthResult = len;
				r = ECARD_SUCCESS;
			}

		}

	}

	cleanup:

	if (cmd_j)
		ctx->env->DeleteLocalRef(cmd_j);

	if (rsp_j)
		ctx->env->ReleaseByteArrayElements(rsp_j, rsp, 0);

	return r;
}

ECARD_STATUS CardReaderGetATR(EIDCLIENT_CARD_READER_HANDLE hCardReader,
		unsigned char* const result, unsigned long* const nLengthResult) {

	unsigned long nlen = *nLengthResult;
	unsigned long len;
	ANDROID_READER_CTX *ctx = (ANDROID_READER_CTX *) hCardReader;

	if (ctx) {
		jbyteArray atr_j = (jbyteArray) ctx->env->CallObjectMethod(ctx->reader,
				ctx->getATR);

		if (atr_j) {

			len = (unsigned long) ctx->env->GetArrayLength(atr_j);

			if (len <= nlen) {
				jbyte* atr = ctx->env->GetByteArrayElements(atr_j, NULL);
				memcpy(result, atr, len);
				*nLengthResult = len;
				ctx->env->ReleaseByteArrayElements(atr_j, atr, 0);

				return ECARD_SUCCESS;
			}
		}
	}

	return ECARD_ERROR;
}
ECARD_STATUS CardReaderSupportsPACE(EIDCLIENT_CARD_READER_HANDLE hCardReader) {
	ALOG("Entered CardReaderSupportsPACE");

	ANDROID_READER_CTX *ctx = (ANDROID_READER_CTX *) hCardReader;

	if (ctx) {
		jboolean supportsPACE = ctx->env->CallBooleanMethod(ctx->reader,
				ctx->supportsPACE);

		if (supportsPACE)
			return ECARD_SUCCESS;
	}

	return ECARD_ERROR;
}

ECARD_STATUS CardReaderDoPACE(EIDCLIENT_CARD_READER_HANDLE hCardReader,
		const enum PinID pinid,
		const nPADataBuffer_t *pin,
		const nPADataBuffer_t *chat,
		const nPADataBuffer_t *certificate_description,
		unsigned int *pace_result,
		unsigned short *status_mse_set_at,
		nPADataBuffer_t *ef_cardaccess,
		nPADataBuffer_t *car_curr,
		nPADataBuffer_t *car_prev,
		nPADataBuffer_t *id_icc)
{
	unsigned char *establishPACEChannelInput_data = NULL;
	size_t establishPACEChannelInput_data_len = 0;

	ECARD_STATUS r;

	r = encode_EstablishPACEChannelInput(pinid, pin->pDataBuffer, pin->bufferSize, chat->pDataBuffer, chat->bufferSize, certificate_description->pDataBuffer, certificate_description->bufferSize, &establishPACEChannelInput_data, &establishPACEChannelInput_data_len);
    if (ECARD_SUCCESS != r)
		return r;

	uint8_t establishPACEChannel_header[] = {0xFF, 0x9A, 0x04, 0x02};
	uint16_t establishPACEChannel_length = 4 + 3 + establishPACEChannelInput_data_len;
    uint8_t* establishPACEChannel = new uint8_t[establishPACEChannel_length];

	memcpy(&establishPACEChannel[0], establishPACEChannel_header, sizeof establishPACEChannel_header);
	establishPACEChannel[4] = 0x00;
	establishPACEChannel[5] = establishPACEChannelInput_data_len / 256;
	establishPACEChannel[6] = establishPACEChannelInput_data_len % 256;
	memcpy(&establishPACEChannel[7], establishPACEChannelInput_data, establishPACEChannelInput_data_len);

	unsigned char result[1024];
	unsigned long result_length = sizeof result;

	r = CardReaderSend(hCardReader, establishPACEChannel, establishPACEChannel_length, result, &result_length);
    if (ECARD_SUCCESS != r)
		return r;

	size_t ef_cardaccess_len, car_curr_len, car_prev_len, id_icc_len;
	r = decode_EstablishPACEChannelOutput(result, result_length, pace_result,
			status_mse_set_at, &ef_cardaccess->pDataBuffer,
			&ef_cardaccess_len, &car_curr->pDataBuffer, &car_curr_len,
			&car_prev->pDataBuffer, &car_prev_len,
			&id_icc->pDataBuffer, &id_icc_len);
	ef_cardaccess->bufferSize = ef_cardaccess_len;
	car_curr->bufferSize = car_curr_len;
	car_prev->bufferSize = car_prev_len;
	id_icc->bufferSize = id_icc_len;

	delete[] establishPACEChannel;
	return r;
}

#ifdef __cplusplus
}
#endif
