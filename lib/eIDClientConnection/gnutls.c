/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

# ifndef __GNUC__
typedef long ssize_t;
# endif

#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GNUTLS_DEBUG_LEVEL 0
#define GNUTLS_CHECK(status) \
	{ \
		if (status < 0) { \
			fprintf (stderr, "*** %s:%d GnuTLS: %s\n",__FILE__ , __LINE__, gnutls_strerror(status)); \
			if (gnutls_error_is_fatal(status)) \
				goto err; \
		} \
	}

struct gnutls_data {
	gnutls_session_t session;
	gnutls_anon_client_credentials_t    anon_credentials;
	gnutls_certificate_credentials_t    certificate_credentials;
	gnutls_psk_client_credentials_t     psk_credentials;
};

static void _gnutls_log_func(int level, const char *const msg)
{
	fprintf(stderr, "GnuTLS Debug: %s", msg);
}

void
gnutls_disconnect(const void *const driver_data)
{
	struct gnutls_data *data;
	ssize_t ret;
	data = (struct gnutls_data *) driver_data;

	do {
		ret = gnutls_bye(data->session, GNUTLS_SHUT_RDWR);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (data->psk_credentials)
		gnutls_psk_free_client_credentials(data->psk_credentials);

	if (data->certificate_credentials)
		gnutls_certificate_free_credentials(data->certificate_credentials);

	gnutls_deinit(data->session);
	gnutls_global_deinit();
}

void *
gnutls_connect(int fd, const unsigned char *const psk, size_t psk_len, const char *const sid, const char *const hostname)
{
	struct gnutls_data *data;
	int status;
	gnutls_datum_t key = {NULL, 0};
	data = (struct gnutls_data *) calloc(1, sizeof * data);

	if (!data) {
		status = GNUTLS_E_INTERNAL_ERROR;
		GNUTLS_CHECK(status);
	}

	/* GnuTLS global initialisation */
	status = gnutls_global_init();
	GNUTLS_CHECK(status);
	gnutls_global_set_log_function(_gnutls_log_func);
	gnutls_global_set_log_level(GNUTLS_DEBUG_LEVEL);
	status = gnutls_init(&(data->session), GNUTLS_CLIENT);
	GNUTLS_CHECK(status);
	gnutls_server_name_set(data->session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
	GNUTLS_CHECK(status);
	/* Pass socket to gnutls */
	gnutls_transport_set_ptr(data->session, (gnutls_transport_ptr_t)(ptrdiff_t) fd);

	if (psk) {
		key.data = (unsigned char *) malloc(psk_len);

		if (!key.data) {
			status = GNUTLS_E_MEMORY_ERROR;
			goto err;
		}

		memcpy(key.data, psk, psk_len);
		key.size = psk_len;
		status = gnutls_priority_set_direct(data->session, "NORMAL:-RSA-PSK:-RSA:-DHE-RSA:-DHE-PSK:+PSK:-DHE-DSS", NULL);
		GNUTLS_CHECK(status);
		status = gnutls_psk_allocate_client_credentials(&(data->psk_credentials));
		GNUTLS_CHECK(status);
		status = gnutls_credentials_set(data->session, GNUTLS_CRD_PSK, data->psk_credentials);
		GNUTLS_CHECK(status);
		status = gnutls_psk_set_client_credentials(data->psk_credentials, sid, &key, GNUTLS_PSK_KEY_HEX);
		GNUTLS_CHECK(status);

	} else {
		status = gnutls_priority_set_direct(data->session, "NORMAL", NULL);
		GNUTLS_CHECK(status);
		status = gnutls_certificate_allocate_credentials(&data->certificate_credentials);
		GNUTLS_CHECK(status);
		status = gnutls_credentials_set(data->session, GNUTLS_CRD_CERTIFICATE, data->certificate_credentials);
		GNUTLS_CHECK(status);
	}

	/* Perform the TLS handshake */
	do {
		status = gnutls_handshake(data->session);
	} while (status < 0 && gnutls_error_is_fatal(status) == 0);

	GNUTLS_CHECK(status);
err:

	if (key.data)
		free(key.data);

	if (gnutls_error_is_fatal(status)) {
		gnutls_disconnect(data);
		data = NULL;
	}

	return data;
}

ssize_t
gnutls_recv(const void *const driver_data, void *const buffer, size_t buffer_size)
{
	struct gnutls_data *data;
	ssize_t ret;

	if (!driver_data)
		return -1;

	data = (struct gnutls_data *) driver_data;

	if (!data) {
		ret = GNUTLS_E_INTERNAL_ERROR;
		GNUTLS_CHECK(ret);
	}

	do {
		ret = gnutls_record_recv(data->session, buffer, buffer_size);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	GNUTLS_CHECK(ret);
err:
	return ret;
}

ssize_t
gnutls_send(const void *const driver_data, const void *const buffer, size_t buffer_size)
{
	struct gnutls_data *data;
	ssize_t ret;
	data = (struct gnutls_data *) driver_data;

	if (!data) {
		ret = GNUTLS_E_INTERNAL_ERROR;
		GNUTLS_CHECK(ret);
	}

	do {
		ret = gnutls_record_send(data->session, buffer, buffer_size);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	GNUTLS_CHECK(ret);
err:
	return ret;
}
