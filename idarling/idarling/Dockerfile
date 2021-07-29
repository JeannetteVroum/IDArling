FROM python:3.8-slim-buster
ENV PYTHONUNBUFFERED 1
#
#Création de l'utilisateur proprietaire de l'applicatif (not root run)
ENV USER=idarling
ENV UID=12345
ENV GID=23456

RUN addgroup --gid $GID $USER
RUN adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "$USER" \
    --uid "$UID" \
    "$USER"

#Installation des librairies nécessaires
RUN apt-get update && apt-get install -y gcc python3-psycopg2 libglib2.0-0  ffmpeg libsm6 libxext6 netcat
#On copie l'application et le script de point d'entrée dans l'image
ARG IDARLING_PATH=/opt/app/

WORKDIR ${IDARLING_PATH}
COPY . ${IDARLING_PATH}

#On modifie l'owner par l'utilisateur crée plus haut
#RUN chown -R $USER:$USER ${IDARLING_PATH}

#USER $USER

#Installation des librairies pythons
RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt
EXPOSE 1234
ENTRYPOINT ["/opt/app/entrypoint.sh"]