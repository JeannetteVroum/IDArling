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

from PyQt5.QtWidgets import QButtonGroup, QPushButton, QLineEdit, QGridLayout, QVBoxLayout, QWidget, QLabel, \
    QDialog

from idarling.shared.commands import UpdateUserName, SignIn
from idarling.shared.error import ErrorMessage

class AuthentificationDialog(QDialog):
    """The dialog shown when an user try to connect a server"""

    def __init__(self, plugin, server):
        super(AuthentificationDialog, self).__init__()
        self._plugin = plugin
        self.server = server
        self.setWindowTitle("Sign In")
        # Setup the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        main_layout = QGridLayout(main)
        layout.addWidget(main)
        username_label = QLabel("<b>Username</b>")
        main_layout.addWidget(username_label, 0, 0)
        self.username = QLineEdit()
        name = self._plugin.config["user"]["name"]
        self.username.setText(name)
        main_layout.addWidget(self.username, 0, 1)
        password_label = QLabel('<b>Password</b>')
        main_layout.addWidget(password_label, 1, 0)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        main_layout.addWidget(self.password, 1, 1)
        button_login = QPushButton("login")
        layout.addWidget(button_login)
        button_login.clicked.connect(self._connect)
        self.my_button_group = QButtonGroup()
        # remove token
        self._plugin.token = None





    def _connect(self):
        username = self.username.text()
        password = self.password.text()
        d = self._plugin.network.send_packet(SignIn.Query(username, password))
        d.add_callback(self._authenticate)
        self.accept()

    def _authenticate(self, reply: SignIn.Reply):
        token = reply.token
        error = reply.error
        name = self.username.text()
        if error is None:
            self._plugin.logger.debug("Try to connect with username %s", name)
            self._plugin.token = token
            self._plugin.core.join_session()
            if self._plugin.config["user"]["name"] != name:
                old_name = self._plugin.config["user"]["name"]
                self._plugin.network.send_packet(UpdateUserName(old_name, name))
                self._plugin.config["user"]["name"] = name
                self._plugin.config["user"]["name"] = name
                self.accept()
        else:
            self._plugin.network.disconnect()
            self._plugin.logger.warning("Error authentification with username %s", name)
            self._plugin.logger.exception(error)
            dialog = ErrorMessage("Fail authentification", error, self._plugin.logger)
            dialog.exec_()
            self._plugin.network.connect(self.server)
            dialog = AuthentificationDialog(self._plugin, self.server)
            if not dialog.exec_():
                self._plugin.network.disconnect()
