# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from enum import Enum


class Error(Enum):
    """
    This class contains the different errors sent by the server
    """
    PERMISSION_NOT_ALLOWED = "Permission not allowed"
    AUTHENTIFICATION_BY_LDAP_DISABLED = "Authentification By LDAP disabled"
    AUTHENTIFICATION_BY_USERNAME_PASSWORD_DISABLED = "Authentification By username/password disabled"
    BAD_CREDENTIALS = "Bad credentials"
    AUTHENTIFICATION_REQUIRED = "Authentification required"
    DATABASE_USED_BY_OTHER_USER = "Database used by another user"
    READER_OR_ANALYST_AFFECTED = "Users are assigned as reader or analyst to the project"
    ERROR_LDAP = "Error LDAP"

    @staticmethod
    def as_enum(d):
        """
        :param d:
        :type d: str
        :return: The Error enum
        :rtype: Error
        """
        if d is not None:
            _, member = d.split('.')
            return getattr(Error, member)

from PyQt5.QtWidgets import QMessageBox


class ErrorMessage(QMessageBox):
    """The MessageBox shown when the action describe in class Error.

    .. seealso:: Error
    """

    def __init__(self, title, error, logger):
        """

        :param title: Title of Dialog
        :type title: str
        :param error: The error Enum
        :type error: Error
        :param logger: logger for write
        :type logger: Logger
        """
        super(ErrorMessage, self).__init__()
        self.setIcon(QMessageBox.Warning)
        self.setWindowTitle(title)
        self.setText(error.value)

