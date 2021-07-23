#!/bin/sh

export NGINXPROXY

envsubst '${NGINX_HOST_NAME} ${DAPHNE_PORT}  ${DAPHNE_HOST}'< /etc/nginx/conf.d/service.template > /etc/nginx/conf.d/default.conf

exec "$@"