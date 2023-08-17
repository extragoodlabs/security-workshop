#!/bin/bash
set -eo pipefail

SSL_ARGS=""

if [ -n "${TLS_CERT_DIR}" ] && [ -d "${TLS_CERT_DIR}" ]; then
    cp "${TLS_CERT_DIR}/tls.key" /etc/ssl/private/
    cp "${TLS_CERT_DIR}/tls.crt" /etc/ssl/certs
    cp "${TLS_CERT_DIR}/ca.crt" /etc/ssl/certs

    chown postgres /etc/ssl/private/*.key
    chown postgres /etc/ssl/certs/*.crt
    chmod 600 /etc/ssl/private/*.key
    chmod 600 /etc/ssl/certs/*.crt

    SSL_ARGS="-c ssl=on -c ssl_cert_file=/etc/ssl/certs/tls.crt -c ssl_key_file=/etc/ssl/private/tls.key -c ssl_ca_file=/etc/ssl/certs/ca.crt"
fi

exec docker-entrypoint.sh postgres ${SSL_ARGS}
