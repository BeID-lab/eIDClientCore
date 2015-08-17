/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#include "de_bdr_eidclient_EIdSession.h"

#include "eCardCore/eCardStatus.h"
#include "eIDClientCore/eIDClientCore.h"
#include "de_bdr_eidclient_external_reader.h"
#include <android/log.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string>

using namespace std;

#define LOG_TAG "eidclient_jni"
#define ALOG(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

typedef struct ChatATClassDescription {
	jclass clazz;
	jmethodID constr;
	jfieldID age_verification;
	jfieldID community_id_verification;
	jfieldID restricted_id;
	jfieldID privileged;
	jfieldID can_allowed;
	jfieldID pin_management;
	jfieldID install_cert;
	jfieldID install_qualified_cert;
	jfieldID read_dg1;
	jfieldID read_dg2;
	jfieldID read_dg3;
	jfieldID read_dg4;
	jfieldID read_dg5;
	jfieldID read_dg6;
	jfieldID read_dg7;
	jfieldID read_dg8;
	jfieldID read_dg9;
	jfieldID read_dg10;
	jfieldID read_dg11;
	jfieldID read_dg12;
	jfieldID read_dg13;
	jfieldID read_dg14;
	jfieldID read_dg15;
	jfieldID read_dg16;
	jfieldID read_dg17;
	jfieldID read_dg18;
	jfieldID read_dg19;
	jfieldID read_dg20;
	jfieldID read_dg21;
	jfieldID write_dg17;
	jfieldID write_dg18;
	jfieldID write_dg19;
	jfieldID write_dg20;
	jfieldID write_dg21;
	jfieldID RFU1;
	jfieldID RFU2;
	jfieldID RFU3;
	jfieldID RFU4;
	jfieldID role;
} ChatATClassDescription_t;

JNIEnv *EID_env;
jobject EID_reader;
static jobject my_obj;

jobject spd_struct_to_jobject(const SPDescription_t &,
		const ChatATClassDescription_t &);
jobject uin_struct_to_jobject(const UserInput_t &,
		const ChatATClassDescription_t &);
NPACLIENT_ERROR uin_jobject_to_struct(jobject, UserInput_t &,
		const ChatATClassDescription_t &);
void chat_get_class_description(ChatATClassDescription_t &);

void state_callback(const NPACLIENT_STATE state, const NPACLIENT_ERROR error) {
	ALOG("state: %ld, error: %ld", state, error);

	jclass clazz = EID_env->FindClass("de/bdr/eidclient/EIdSession");
	jmethodID update_status = EID_env->GetMethodID(clazz, "updateStatus",
			"(II)V");

	EID_env->CallVoidMethod(my_obj, update_status, state, error);

	EID_env->DeleteLocalRef(clazz);
}

NPACLIENT_ERROR nPAeIdUserInteractionCallback(
		const SPDescription_t *description, UserInput_t *input) {

	ALOG("entered nPAeIdUserInteractionCallback");
	NPACLIENT_ERROR err = NPACLIENT_ERROR_SUCCESS;

	ChatATClassDescription_t chat_desc;
	jclass clazz = EID_env->FindClass("de/bdr/eidclient/EIdSession");

	jmethodID user_callback = EID_env->GetMethodID(clazz,
			"userInteractionCallback",
			"(Lde/bdr/eidclient/SPDescription;Lde/bdr/eidclient/UserInput;)Z");

	chat_get_class_description(chat_desc);

	jobject spd = spd_struct_to_jobject(*description, chat_desc);

	jobject user_input = uin_struct_to_jobject(*input, chat_desc);

	jboolean suc = EID_env->CallBooleanMethod(my_obj, user_callback, spd,
			user_input);

	if (!suc) {
		err = NPACLIENT_ERROR_GUI_ABORT;
	} else {
		err = uin_jobject_to_struct(user_input, *input, chat_desc);
	}

	//cleanup
	EID_env->DeleteLocalRef(clazz);
	EID_env->DeleteLocalRef(spd);
	EID_env->DeleteLocalRef(user_input);
	EID_env->DeleteLocalRef(chat_desc.clazz);

	return err;
}

void chat_get_class_description(ChatATClassDescription_t &desc) {
	//clazz
	desc.clazz = EID_env->FindClass("de/bdr/eidclient/Chat$AT");

	//constructor
	desc.constr = EID_env->GetMethodID(desc.clazz, "<init>", "()V");

	//ageVerification
	desc.age_verification = EID_env->GetFieldID(desc.clazz, "ageVerification",
			"Z");

	//communityIdVerification
	desc.community_id_verification = EID_env->GetFieldID(desc.clazz,
			"communityIdVerification", "Z");

	//restrictedId
	desc.restricted_id = EID_env->GetFieldID(desc.clazz, "restrictedId", "Z");

	//privileged
	desc.privileged = EID_env->GetFieldID(desc.clazz, "privileged", "Z");

	//canAllowed
	desc.can_allowed = EID_env->GetFieldID(desc.clazz, "canAllowed", "Z");

	//pinManagement
	desc.pin_management = EID_env->GetFieldID(desc.clazz, "pinManagement", "Z");

	//installCert
	desc.install_cert = EID_env->GetFieldID(desc.clazz, "installCert", "Z");

	//installQualifiedCert
	desc.install_qualified_cert = EID_env->GetFieldID(desc.clazz,
			"installQualifiedCert", "Z");

	//readDG1
	desc.read_dg1 = EID_env->GetFieldID(desc.clazz, "readDG1", "Z");

	//readDG2
	desc.read_dg2 = EID_env->GetFieldID(desc.clazz, "readDG2", "Z");

	//readDG3
	desc.read_dg3 = EID_env->GetFieldID(desc.clazz, "readDG3", "Z");

	//readDG4
	desc.read_dg4 = EID_env->GetFieldID(desc.clazz, "readDG4", "Z");

	//readDG5
	desc.read_dg5 = EID_env->GetFieldID(desc.clazz, "readDG5", "Z");

	//readDG6
	desc.read_dg6 = EID_env->GetFieldID(desc.clazz, "readDG6", "Z");

	//readDG7
	desc.read_dg7 = EID_env->GetFieldID(desc.clazz, "readDG7", "Z");

	//readDG8
	desc.read_dg8 = EID_env->GetFieldID(desc.clazz, "readDG8", "Z");

	//readDG9
	desc.read_dg9 = EID_env->GetFieldID(desc.clazz, "readDG9", "Z");

	//readDG10
	desc.read_dg10 = EID_env->GetFieldID(desc.clazz, "readDG10", "Z");

	//readDG11
	desc.read_dg11 = EID_env->GetFieldID(desc.clazz, "readDG11", "Z");

	//readDG12
	desc.read_dg12 = EID_env->GetFieldID(desc.clazz, "readDG12", "Z");

	//readDG13
	desc.read_dg13 = EID_env->GetFieldID(desc.clazz, "readDG13", "Z");

	//readDG14
	desc.read_dg14 = EID_env->GetFieldID(desc.clazz, "readDG14", "Z");

	//readDG15
	desc.read_dg15 = EID_env->GetFieldID(desc.clazz, "readDG15", "Z");

	//readDG16
	desc.read_dg16 = EID_env->GetFieldID(desc.clazz, "readDG16", "Z");

	//readDG17
	desc.read_dg17 = EID_env->GetFieldID(desc.clazz, "readDG17", "Z");

	//readDG18
	desc.read_dg18 = EID_env->GetFieldID(desc.clazz, "readDG18", "Z");

	//readDG19
	desc.read_dg19 = EID_env->GetFieldID(desc.clazz, "readDG19", "Z");

	//readDG20
	desc.read_dg20 = EID_env->GetFieldID(desc.clazz, "readDG20", "Z");

	//readDG21
	desc.read_dg21 = EID_env->GetFieldID(desc.clazz, "readDG21", "Z");

	//writeDG17
	desc.write_dg17 = EID_env->GetFieldID(desc.clazz, "writeDG17", "Z");

	//writeDG18
	desc.write_dg18 = EID_env->GetFieldID(desc.clazz, "writeDG18", "Z");

	//writeDG19
	desc.write_dg19 = EID_env->GetFieldID(desc.clazz, "writeDG19", "Z");

	//writeDG20
	desc.write_dg20 = EID_env->GetFieldID(desc.clazz, "writeDG20", "Z");

	//writeDG21
	desc.write_dg21 = EID_env->GetFieldID(desc.clazz, "writeDG21", "Z");

	//rFU1
	desc.RFU1 = EID_env->GetFieldID(desc.clazz, "rFU1", "Z");

	//rFU2
	desc.RFU2 = EID_env->GetFieldID(desc.clazz, "rFU2", "Z");

	//rFU3
	desc.RFU3 = EID_env->GetFieldID(desc.clazz, "rFU3", "Z");

	//rFU4
	desc.RFU4 = EID_env->GetFieldID(desc.clazz, "rFU4", "Z");

	//role
	desc.role = EID_env->GetFieldID(desc.clazz, "role", "Z");
}

NPACLIENT_ERROR chat_jobject_to_struct(jobject c,
		const ChatATClassDescription_t &desc, struct chat &chat_r) {

	if (c == NULL)
		return NPACLIENT_ERRO;

	//ageVerification
	chat_r.authorization.at.age_verification = (char) EID_env->GetBooleanField(c,
			desc.age_verification);

	//communityIdVerification
	chat_r.authorization.at.community_id_verification =
			(char) EID_env->GetBooleanField(c, desc.community_id_verification);

	//restrictedId
	chat_r.authorization.at.restricted_id = (char) EID_env->GetBooleanField(c,
			desc.restricted_id);

	//privileged
	chat_r.authorization.at.privileged = (char) EID_env->GetBooleanField(c,
			desc.privileged);

	//canAllowed
	chat_r.authorization.at.can_allowed = (char) EID_env->GetBooleanField(c,
			desc.can_allowed);

	//pinManagement
	chat_r.authorization.at.pin_management = (char) EID_env->GetBooleanField(c,
			desc.pin_management);

	//installCert
	chat_r.authorization.at.install_cert = (char) EID_env->GetBooleanField(c,
			desc.install_cert);

	//installQualifiedCert
	chat_r.authorization.at.install_qualified_cert =
			(char) EID_env->GetBooleanField(c, desc.install_qualified_cert);

	//readDG1
	chat_r.authorization.at.read_dg1 = (char) EID_env->GetBooleanField(c,
			desc.read_dg1);

	//readDG2
	chat_r.authorization.at.read_dg2 = (char) EID_env->GetBooleanField(c,
			desc.read_dg2);

	//readDG3
	chat_r.authorization.at.read_dg3 = (char) EID_env->GetBooleanField(c,
			desc.read_dg3);

	//readDG4
	chat_r.authorization.at.read_dg4 = (char) EID_env->GetBooleanField(c,
			desc.read_dg4);

	//readDG5
	chat_r.authorization.at.read_dg5 = (char) EID_env->GetBooleanField(c,
			desc.read_dg5);

	//readDG6
	chat_r.authorization.at.read_dg6 = (char) EID_env->GetBooleanField(c,
			desc.read_dg6);

	//readDG7
	chat_r.authorization.at.read_dg7 = (char) EID_env->GetBooleanField(c,
			desc.read_dg7);

	//readDG8
	chat_r.authorization.at.read_dg8 = (char) EID_env->GetBooleanField(c,
			desc.read_dg8);

	//readDG9
	chat_r.authorization.at.read_dg9 = (char) EID_env->GetBooleanField(c,
			desc.read_dg9);

	//readDG10
	chat_r.authorization.at.read_dg10 = (char) EID_env->GetBooleanField(c,
			desc.read_dg10);

	//readDG11
	chat_r.authorization.at.read_dg11 = (char) EID_env->GetBooleanField(c,
			desc.read_dg11);

	//readDG12
	chat_r.authorization.at.read_dg12 = (char) EID_env->GetBooleanField(c,
			desc.read_dg12);

	//readDG13
	chat_r.authorization.at.read_dg13 = (char) EID_env->GetBooleanField(c,
			desc.read_dg13);

	//readDG14
	chat_r.authorization.at.read_dg14 = (char) EID_env->GetBooleanField(c,
			desc.read_dg14);

	//readDG15
	chat_r.authorization.at.read_dg15 = (char) EID_env->GetBooleanField(c,
			desc.read_dg15);

	//readDG16
	chat_r.authorization.at.read_dg16 = (char) EID_env->GetBooleanField(c,
			desc.read_dg16);

	//readDG17
	chat_r.authorization.at.read_dg17 = (char) EID_env->GetBooleanField(c,
			desc.read_dg17);

	//readDG18
	chat_r.authorization.at.read_dg18 = (char) EID_env->GetBooleanField(c,
			desc.read_dg18);

	//readDG19
	chat_r.authorization.at.read_dg19 = (char) EID_env->GetBooleanField(c,
			desc.read_dg19);

	//readDG20
	chat_r.authorization.at.read_dg20 = (char) EID_env->GetBooleanField(c,
			desc.read_dg20);

	//readDG21
	chat_r.authorization.at.read_dg21 = (char) EID_env->GetBooleanField(c,
			desc.read_dg21);

	//writeDG17
	chat_r.authorization.at.write_dg17 = (char) EID_env->GetBooleanField(c,
			desc.write_dg17);

	//writeDG18
	chat_r.authorization.at.write_dg18 = (char) EID_env->GetBooleanField(c,
			desc.write_dg18);

	//writeDG19
	chat_r.authorization.at.write_dg19 = (char) EID_env->GetBooleanField(c,
			desc.write_dg19);

	//writeDG20
	chat_r.authorization.at.write_dg20 = (char) EID_env->GetBooleanField(c,
			desc.write_dg20);

	//writeDG21
	chat_r.authorization.at.write_dg21 = (char) EID_env->GetBooleanField(c,
			desc.write_dg21);

	//rFU1
	chat_r.authorization.at.RFU1 = (char) EID_env->GetBooleanField(c, desc.RFU1);

	//rFU2
	chat_r.authorization.at.RFU2 = (char) EID_env->GetBooleanField(c, desc.RFU2);

	//rFU3
	chat_r.authorization.at.RFU3 = (char) EID_env->GetBooleanField(c, desc.RFU3);

	//rFU4
	chat_r.authorization.at.RFU4 = (char) EID_env->GetBooleanField(c, desc.RFU4);

	//role
	chat_r.authorization.at.role = (char) EID_env->GetBooleanField(c, desc.role);

	return NPACLIENT_ERROR_SUCCESS;

}

jobject chat_struct_to_jobject(const struct chat& chat,
		const ChatATClassDescription_t &desc) {

	if (chat.type != TT_AT)
		return NULL;

	jobject c = EID_env->NewObject(desc.clazz, desc.constr);

	if (!c)
		return NULL;

	//ageVerification
	EID_env->SetBooleanField(c, desc.age_verification,
			(jboolean) chat.authorization.at.age_verification);

	//communityIdVerification
	EID_env->SetBooleanField(c, desc.community_id_verification,
			(jboolean) chat.authorization.at.community_id_verification);

	//restrictedId
	EID_env->SetBooleanField(c, desc.restricted_id,
			(jboolean) chat.authorization.at.restricted_id);

	//privileged
	EID_env->SetBooleanField(c, desc.privileged,
			(jboolean) chat.authorization.at.privileged);

	//canAllowed
	EID_env->SetBooleanField(c, desc.can_allowed,
			(jboolean) chat.authorization.at.can_allowed);

	//pinManagement
	EID_env->SetBooleanField(c, desc.pin_management,
			(jboolean) chat.authorization.at.pin_management);

	//installCert
	EID_env->SetBooleanField(c, desc.install_cert,
			(jboolean) chat.authorization.at.install_cert);

	//installQualifiedCert
	EID_env->SetBooleanField(c, desc.install_qualified_cert,
			(jboolean) chat.authorization.at.install_qualified_cert);

	//readDG1
	EID_env->SetBooleanField(c, desc.read_dg1,
			(jboolean) chat.authorization.at.read_dg1);

	//readDG2
	EID_env->SetBooleanField(c, desc.read_dg2,
			(jboolean) chat.authorization.at.read_dg2);

	//readDG3
	EID_env->SetBooleanField(c, desc.read_dg3,
			(jboolean) chat.authorization.at.read_dg3);

	//readDG4
	EID_env->SetBooleanField(c, desc.read_dg4,
			(jboolean) chat.authorization.at.read_dg4);

	//readDG5
	EID_env->SetBooleanField(c, desc.read_dg5,
			(jboolean) chat.authorization.at.read_dg5);

	//readDG6
	EID_env->SetBooleanField(c, desc.read_dg6,
			(jboolean) chat.authorization.at.read_dg6);

	//readDG7
	EID_env->SetBooleanField(c, desc.read_dg7,
			(jboolean) chat.authorization.at.read_dg7);

	//readDG8
	EID_env->SetBooleanField(c, desc.read_dg8,
			(jboolean) chat.authorization.at.read_dg8);

	//readDG9
	EID_env->SetBooleanField(c, desc.read_dg9,
			(jboolean) chat.authorization.at.read_dg9);

	//readDG10
	EID_env->SetBooleanField(c, desc.read_dg10,
			(jboolean) chat.authorization.at.read_dg10);

	//readDG11
	EID_env->SetBooleanField(c, desc.read_dg11,
			(jboolean) chat.authorization.at.read_dg11);

	//readDG12
	EID_env->SetBooleanField(c, desc.read_dg12,
			(jboolean) chat.authorization.at.read_dg12);

	//readDG13
	EID_env->SetBooleanField(c, desc.read_dg13,
			(jboolean) chat.authorization.at.read_dg13);

	//readDG14
	EID_env->SetBooleanField(c, desc.read_dg14,
			(jboolean) chat.authorization.at.read_dg14);

	//readDG15
	EID_env->SetBooleanField(c, desc.read_dg15,
			(jboolean) chat.authorization.at.read_dg15);

	//readDG16
	EID_env->SetBooleanField(c, desc.read_dg16,
			(jboolean) chat.authorization.at.read_dg16);

	//readDG17
	EID_env->SetBooleanField(c, desc.read_dg17,
			(jboolean) chat.authorization.at.read_dg17);

	//readDG18
	EID_env->SetBooleanField(c, desc.read_dg18,
			(jboolean) chat.authorization.at.read_dg18);

	//readDG19
	EID_env->SetBooleanField(c, desc.read_dg19,
			(jboolean) chat.authorization.at.read_dg19);

	//readDG20
	EID_env->SetBooleanField(c, desc.read_dg20,
			(jboolean) chat.authorization.at.read_dg20);

	//readDG21
	EID_env->SetBooleanField(c, desc.read_dg21,
			(jboolean) chat.authorization.at.read_dg21);

	//writeDG17
	EID_env->SetBooleanField(c, desc.write_dg17,
			(jboolean) chat.authorization.at.write_dg17);

	//writeDG18
	EID_env->SetBooleanField(c, desc.write_dg18,
			(jboolean) chat.authorization.at.write_dg18);

	//writeDG19
	EID_env->SetBooleanField(c, desc.write_dg19,
			(jboolean) chat.authorization.at.write_dg19);

	//writeDG20
	EID_env->SetBooleanField(c, desc.write_dg20,
			(jboolean) chat.authorization.at.write_dg20);

	//writeDG21
	EID_env->SetBooleanField(c, desc.write_dg21,
			(jboolean) chat.authorization.at.write_dg21);

	//rFU1
	EID_env->SetBooleanField(c, desc.RFU1,
			(jboolean) chat.authorization.at.RFU1);

	//rFU2
	EID_env->SetBooleanField(c, desc.RFU2,
			(jboolean) chat.authorization.at.RFU2);

	//rFU3
	EID_env->SetBooleanField(c, desc.RFU3,
			(jboolean) chat.authorization.at.RFU3);

	//rFU4
	EID_env->SetBooleanField(c, desc.RFU4,
			(jboolean) chat.authorization.at.RFU4);

	//role
	EID_env->SetBooleanField(c, desc.role,
			(jboolean) chat.authorization.at.role);

	return c;
}

jobject spd_struct_to_jobject(const SPDescription_t &description,
		const ChatATClassDescription_t &chat_desc) {

	jobject res = NULL;

	jclass clazz = EID_env->FindClass("de/bdr/eidclient/SPDescription");
	jmethodID constr =
			EID_env->GetMethodID(clazz, "<init>",
					"(BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;JJLde/bdr/eidclient/Chat;Lde/bdr/eidclient/Chat;)V");

	//name
	char *name_str = strndup((char *) description.name.pDataBuffer,
			description.name.bufferSize);
	if (!name_str)
		return NULL;
	jstring p_name = EID_env->NewStringUTF(name_str);
	free(name_str);

	//description
	char *desc_str = strndup((char *) description.description.pDataBuffer,
			description.description.bufferSize);
	if (!desc_str)
		return NULL;
	jstring p_desc = EID_env->NewStringUTF(desc_str);
	free(desc_str);

	//description_type
	jbyte p_desc_type = (jbyte) description.description_type;

	//url
	char *url_str = strndup((char *) description.url.pDataBuffer,
			description.url.bufferSize);
	if (!url_str)
		return NULL;
	jstring p_url = EID_env->NewStringUTF(url_str);
	free(url_str);

	//valid_from
	jlong p_valid_from = (jlong) static_cast<long int>(description.valid_from);

	//valid_to
	jlong p_valid_to = (jlong) static_cast<long int>(description.valid_to);

	//chat_required
	jobject p_chat_req = chat_struct_to_jobject(description.chat_required,
			chat_desc);

	//chat_optional
	jobject p_chat_opt = chat_struct_to_jobject(description.chat_optional,
			chat_desc);

	res = EID_env->NewObject(clazz, constr, p_desc_type, p_name, p_desc, p_url,
			p_valid_from, p_valid_to, p_chat_req, p_chat_opt);

	//Cleanup
	cleanup: EID_env->DeleteLocalRef(p_name);
	EID_env->DeleteLocalRef(p_desc);
	EID_env->DeleteLocalRef(p_url);
	EID_env->DeleteLocalRef(p_chat_opt);
	EID_env->DeleteLocalRef(p_chat_req);
	EID_env->DeleteLocalRef(clazz);

	return res;
}

jobject uin_struct_to_jobject(const UserInput_t &input,
		const ChatATClassDescription_t &desc) {
	jclass clazz = EID_env->FindClass("de/bdr/eidclient/UserInput");

	jmethodID constr = EID_env->GetMethodID(clazz, "<init>",
			"(ZBLde/bdr/eidclient/Chat;Ljava/lang/String;)V");

	jboolean p_pin_required = (jboolean) input.pin_required;
	jbyte p_pin_id = (jbyte) input.pin_id;
	jobject p_chat_selected = chat_struct_to_jobject(input.chat_selected, desc);

	jobject res = EID_env->NewObject(clazz, constr, p_pin_required, p_pin_id,
			p_chat_selected, NULL);

	EID_env->DeleteLocalRef(clazz);

	return res;
}

NPACLIENT_ERROR uin_jobject_to_struct(jobject uin, UserInput_t &res,
		const ChatATClassDescription_t &desc) {

	//omits const struct members: pin_required, pin_id;

	NPACLIENT_ERROR err = NPACLIENT_ERROR_SUCCESS;

	if (uin == NULL)
		return NPACLIENT_ERRO;

	jclass clazz = EID_env->FindClass("de/bdr/eidclient/UserInput");

	//PIN
	jfieldID pin_fid = EID_env->GetFieldID(clazz, "pin", "Ljava/lang/String;");
	jstring jpin = (jstring) EID_env->GetObjectField(uin, pin_fid);

	char const *pin = EID_env->GetStringUTFChars(jpin, 0);

	if (pin != NULL) {
		strncpy((char *) res.pin.pDataBuffer, pin, MAX_PIN_SIZE);
		res.pin.bufferSize = strlen(pin);

		EID_env->ReleaseStringUTFChars(jpin, pin);
	}

	//Chat_Selected
	jfieldID chat_sel_fid = EID_env->GetFieldID(clazz, "chatSelected",
			"Lde/bdr/eidclient/Chat;");
	jobject chat_sel_obj = EID_env->GetObjectField(uin, chat_sel_fid);

	err = chat_jobject_to_struct(chat_sel_obj, desc, res.chat_selected);

	//cleanup
	EID_env->DeleteLocalRef(clazz);
	EID_env->DeleteLocalRef(chat_sel_obj);

	return err;
}

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_de_bdr_eidclient_EIdSession_performEAC(
		JNIEnv *pEnv, jobject pThis, jobject reader, jstring url,
		jstring session_id, jstring path_sec) {

	ALOG("Entered CoreWrapper performEAC");

	if(reader == NULL){
		ALOG("Reader Parameter is null");
		return NPACLIENT_ERROR_INVALID_PARAMETER1;
	}
	if(url == NULL){
		ALOG("URL Parameter is null");
		return NPACLIENT_ERROR_INVALID_PARAMETER2;
	}

	EID_env = pEnv;
	my_obj = pThis;

	const char *url_str;
	const char *session_id_str;
	const char *path_sec_str;

	unsigned long retValue = 0;

	EID_reader = reader;

	if (retValue)
		return retValue;

	url_str = pEnv->GetStringUTFChars(url, 0);
	session_id_str = pEnv->GetStringUTFChars(session_id, 0);
	path_sec_str = pEnv->GetStringUTFChars(path_sec, 0);

	retValue = nPAeIdPerformAuthenticationProtocol(READER_EXTERNAL, url_str,
			session_id_str, path_sec_str, NULL, NULL, nPAeIdUserInteractionCallback,
			state_callback);

	ALOG("Authentication returned value: 0x%08lx", retValue);

	pEnv->ReleaseStringUTFChars(url, url_str);
	pEnv->ReleaseStringUTFChars(session_id, session_id_str);
	pEnv->ReleaseStringUTFChars(path_sec, path_sec_str);

	return (jlong) retValue;
}

JNIEXPORT void JNICALL Java_de_bdr_eidclient_EIdSession_pipeStdOut
  (JNIEnv *pEnv, jobject pObject){
	ALOG("Entered pipeStdOut");
	char readBuffer[256] = {0};
	int pipes[2];
	pipe(pipes);
	dup2(pipes[1], STDOUT_FILENO);
	FILE *inputFile = fdopen(pipes[0], "r");

	while (1) {
		fgets(readBuffer, sizeof(readBuffer), inputFile);
		__android_log_write(2, "EID_CLIENT_CORE_STDOUT", readBuffer);
	}
}


#ifdef __cplusplus
}
#endif
