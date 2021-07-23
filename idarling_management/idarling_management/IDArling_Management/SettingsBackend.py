import logging

from IDArling_management.models import Groups
from django.contrib.auth.models import User
from ldap3 import Server, Connection, ALL


class AuthentificationBackend(object):
    # Get an instance of a logger
    logger = logging.getLogger(__name__)

    def authenticate(self, request, username=None, password=None):
        try:
            server = Server(self.LDAP_URL, get_info=ALL)
            connection = Connection(server, user=username, password=password)
            g = Groups.objects.all()
            if not connection.bind():
                return None
            else:
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    user = User(username=username)
                    user.save()
                    logging.info("User %s from LDAP register" % user.username)
                return user
        except Exception as e:
            logging.error("Exception LDAP %s" % e)

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
