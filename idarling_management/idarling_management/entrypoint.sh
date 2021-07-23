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


python manage.py makemigrations
python manage.py migrate

if [ -z "$DJANGO_SUPERUSER_USERNAME" ] ||  [ -z "$DJANGO_SUPERUSER_PASSWORD" ]
then
  echo "No admin register..."
else
  echo "create administrator account"
  python manage.py createsuperuser \
        --noinput
fi


exec  /home/djangoUser/.local/bin/daphne  IDArling_Management.asgi:application --bind $DJANGO_IP -p $DJANGO_PORT