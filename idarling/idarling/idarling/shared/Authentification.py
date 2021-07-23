# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import configparser
import secrets
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
from typing import Optional, Union

import base64
import hashlib
import ldap3
import os
from ldap3 import Server, Connection

from idarling.shared import error, utils
from idarling.shared.error import Error
from idarling.shared.models import User
from idarling.shared.utils import force_bytes


class Authentification():

    def __init__(self, logger, parent):
        self._logger = logger
        self._parent = parent
        config = configparser.ConfigParser()
        cwd, _ = os.path.split(os.path.abspath(__file__))
        path = os.path.join(cwd, "..", "..", "setting_server.ini")
        config.read(path)



        host = os.environ.get("LDAP_HOST", config["LDAP"]["host"])
        port =os.environ.get("LDAP_PORT", config["LDAP"]["port"])
        self.base_dn = os.environ.get("LDAP_BASE_DN", "None")
        LDAP_URL = "ldap://%s:%s" % (host, port)
        self.server = Server(LDAP_URL, use_ssl=True, get_info=True)


    def authenticate_ldap(self, username: str, password: str) -> bool:
        username, search_base = utils.searchDc(username)
        user_base = "cn=%s,%s" % (username,self.base_dn)
        connection = Connection(self.server, user_base, password)
        try:
            self._logger.info(f"Base_dn {user_base} try to authenticate")
            if not connection.bind():
                self._logger.warning("Connection refused for {} , reason : {}".format(username, connection.result))
                return error.Error.BAD_CREDENTIALS
            return True
        except Exception as e:
            self._logger.error("Exception %s " % e)
            return error.Error.ERROR_LDAP

    def authentication_not_ldap(self, username: str, password: str) -> Union[bool, Error]:
        algo_digest, iterations, salt, hash = self._parent.storage.get_hash_user(username)
        # Iteration is in String field from database
        iterations = int(iterations)
        digest = algo_digest.split('_')[1]
        hash_calculate = self.pbkdf2(password, salt, digest, iterations)
        if not self.constant_time_compare(hash_calculate, hash):
            self._logger.warning("Bad Password")
            return error.Error.BAD_CREDENTIALS
        else:
            self._logger.info("Successful Authentication")
            return True

    def authenticate(self, username, password) -> Union[bool, Error]:
        self._parent.storage.refresh_session()
        ldap_allowed: bool = self._parent.storage.get_authentification_by_ldap_is_allowed()
        local_account_allowed: bool = self._parent.storage.get_authentification_by_username_password_is_allowed()
        user_wanted: Optional[User] = self._parent.storage.select_user_by_username(username=username)
        if user_wanted is not None:
            self._logger.debug(f"Attempt to authenticate the user {username}")
            self._logger.debug(f"ldap_user ? : {user_wanted.ldap_user}")
            self._logger.debug(f"authentificationByPassword ? : {user_wanted.authentificationByPassword}")
            if user_wanted.ldap_user and ldap_allowed:
                return self.authenticate_ldap(username, password)
            if user_wanted.authentificationByPassword and local_account_allowed:
                return self.authentication_not_ldap(username, password)
        elif ldap_allowed and user_wanted is not None:
            # check if user exist in LDAP server
            retour = self.authenticate_ldap(username, password)
            if not (isinstance(retour, error.Error)):
                self.create_ldap_account(username, password)
                return True
            else:
                return retour
        return error.Error.BAD_CREDENTIALS

    def constant_time_compare(self, val1, val2):
        """Return True if the two strings are equal, False otherwise.
        From django/utils/crypto.py"""
        return secrets.compare_digest(force_bytes(val1), force_bytes(val2))

    def pbkdf2(self, password, salt, digest, iterations):
        password = force_bytes(password)
        salt = force_bytes(salt)
        hash = hashlib.pbkdf2_hmac(digest, password, salt, iterations)
        hash = base64.b64encode(hash).decode('ascii').strip()
        return hash

    def getUserByEmailOrUsername(self, authentification_parameter):
        if "@" in authentification_parameter:
            return self._parent.storage.select_user_by_email(authentification_parameter)
        return self._parent.storage.select_user_by_username(authentification_parameter)

    def create_ldap_account(self, username, password) -> None:
        is_email = '@' in username
        if is_email:
            username, search_base = utils.searchDc(username)
            connection = Connection(self.server, username, password)
            connection.bind()
            connection.search(search_base, '(objectclass=person)', ldap3.SUBTREE,
                              attributes=['userPrincipalName', 'sAMAccountName'])
            for entrie in connection.entries:
                if entrie['sAMAccountName'] == username:
                    email = entrie['userPrincipalName']
                    user_without_email = self.getUserByEmailOrUsername(username)
                    if user_without_email is not None:
                        self._parent.storage.update_email(user_without_email, email)
                        return user_without_email
                    # create user account
                    self._parent.storage.register_user_ldap(username=username, email=email)
        else:
            self._parent.storage.register_user_ldap(username=username)
