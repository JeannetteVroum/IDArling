#!/usr/bin/env bash
# entrypoint.sh

if [ "$SQL_HOST" ]
then
    echo "Waiting for postgres..."

    while ! nc -z $SQL_HOST $SQL_PORT; do
      echo "Waiting for postgres..."
      sleep 5
    done

    echo "PostgreSQL started"
fi

if [ "$SSL" ]
then
  exec python idarling_server.py -h $IDARLING_IP  -p $IDARLING_PORT --ssl ./certificates/certificate.crt ./certificates/privateKey.key -l $IDARLING_LEVEL_LOG
else
  exec python idarling_server.py -h $IDARLING_IP  -p $IDARLING_PORT --no-ssl -l $IDARLING_LEVEL_LOG
fi