# syntax=docker/dockerfile:1
FROM python:3.6-alpine
ENV PYTHONUNBUFFERED 1
#
#Creation d'un utilisateur djangoUser qui sera l'utilisateur éxecutant le code (non sudoer)
ENV USER=djangoUser
ENV UID=12345
ENV GID=23456

#On installe les dépauts nécessaire au fonctionnement de l'application
RUN apk update
RUN apk add --no-cache  py3-virtualenv gcc  postgresql-dev  python3-dev musl-dev libffi-dev bash netcat-openbsd
#L'application sera placée dans le dossier /opt/app/
ARG IDARLING_PATH=/srv/IDArling_Management/

RUN mkdir ${IDARLING_PATH}
#On copie l'archive et le script d'entrée dans l'image
COPY . ${IDARLING_PATH}
WORKDIR ${IDARLING_PATH}
#On rend éxecutable le point d'entrée et on rajoute le nouvel utilisateur
RUN chmod 755 entrypoint.sh
RUN addgroup --gid $GID $USER
RUN adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "$USER" \
    --uid "$UID" \
    "$USER"

#&& ln -sf /dev/stdout /var/log/idarling_management.log
RUN chown -R $USER:$USER /var/log
RUN chown -R $USER:$USER ${IDARLING_PATH}
#RUN chown -R $USER:$USER /var/log/idarling_management.log
USER $USER

RUN pip install --upgrade pip
RUN  pip install -r requirements.txt

STOPSIGNAL SIGTERM


ENTRYPOINT ["/srv/IDArling_Management/entrypoint.sh"]
