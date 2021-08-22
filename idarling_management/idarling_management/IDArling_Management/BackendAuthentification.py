#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from ldap3 import Server, Connection, ALL

from IDArling.models import Settings
from IDArling_Management.utils.Utils_Data import UtilsData

User = get_user_model()
logger = logging.getLogger(__name__)


class BackendAuthentification(ModelBackend):

    def getUserByEmailOrUsername(authentification_parameter):
        try:
            if "@" in authentification_parameter:
                return User.objects.get(email=authentification_parameter)
            else:
                return User.objects.get(username=authentification_parameter)
        except User.DoesNotExist:
            logger.error(f"User {authentification_parameter} doesn't exist")
            return None

    def authenticate_ldap(username: str, password: str) -> bool:
        LDAP_URL = "ldap://%s:%s" % (settings.LDAP["URL"], settings.LDAP["PORT"])
        if '@' in username:
            _, search_base = UtilsData.searchDc(username)
        server = Server(LDAP_URL, get_info=ALL)
        # OU userPrincipalName
        connection = Connection(server, user=username, password=password, auto_bind=True)
        if not connection.bind():
            logging.info("Connection refused for {} , reason : {}".format(username, connection.result))
            return False
        return True

    def create_ldap_account(email, password):
        username, search_base = UtilsData.searchDc(email)
        print(f"settings_ldap is {settings.LDAP['BASE_DN']}")
        user = get_user_model().objects.create_user(username=username, email=email, password=None,
                                                    ldap_user=True)
        return user

    def validate_email(email):
        """

        """
        from django.core.validators import EmailValidator
        from django.core.exceptions import ValidationError
        try:
            validator = EmailValidator()
            validator(email)
            user_part, domain_part = email.rsplit('@', 1)
            if domain_part not in settings.LDAP["DOMAIN_ALLOWED"]:
                return False
            return True
        except ValidationError:
            return False

    def authenticate(username=None, password=None):
        authentification_password_allowed = Settings.objects.first().authentification_username_password
        authentification_ldap_allowed = Settings.objects.first().authentification_ldap
        user_wanted_to_connect: User = BackendAuthentification.getUserByEmailOrUsername(
            authentification_parameter=username)
        logger.info(f"User {username}  exist ? {user_wanted_to_connect}")
        logger.info(f"Password is {password}")
        # If user is already register
        if user_wanted_to_connect is not None:
            # ldap account and authentification by ldap is allowed
            # try to authenticate him
            if user_wanted_to_connect.ldap_user and authentification_ldap_allowed:
                if BackendAuthentification.authenticate_ldap(username=username, password=password):
                    return user_wanted_to_connect
                else:
                    return None
            # not LDAP account
            elif authentification_password_allowed:
                return BackendAuthentification.authenticate_not_ldap(username, password)
        # User is not registered
        elif authentification_ldap_allowed and BackendAuthentification.validate_email(username):
            logger.info(f"Try authenticate user {username} with LDAP")
            if BackendAuthentification.authenticate_ldap(username, password):
                user = BackendAuthentification.create_ldap_account(username, password)
                # set User affectation
                user.set_create_default_permissions()
                return user
        return None

    def register_user_normal(username=None, password=None) -> User:
        user = get_user_model().objects.create_user(username=username, password=password,
                                                    authentificationByPassword=True)
        return user

    def authenticate_not_ldap(username=None, password=None):
        """ Check password for a user
        if the password matches return user and ok code return
        else return None and False
        :param password:
        :type password: str
        :return: User, code
        :rtype: User , dict
        """
        try:
            user = User.objects.get(username=username)
            return user if user.check_password(password) else None
        except:
            return None

    def create_user(username=None, password=None):
        """Create user"""
        try:
            user = User.objects.get(username=username)
            if user:
                retour = dict()
                retour["error"] = list()
                retour["error"].append("User already exists")
                logging.info("User %s already exists " % username)
        except User.DoesNotExist:
            user = BackendAuthentification.register_user_normal(username=username, password=password)
            logging.info("User %s registred " % username)
            retour = {"return": True}
        return user, retour

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
