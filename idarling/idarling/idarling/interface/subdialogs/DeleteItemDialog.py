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

from PyQt5.QtWidgets import QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QWidget, QDialog

from idarling.shared.commands import DeleteItem
from idarling.shared.error import ErrorMessage
from idarling.shared.models import Database, Project, File, Folder


class DeleteItemDialog(QDialog):
    "The dialog shown when an user wants to delete a project/folder/file or snapshot."""

    def __init__(self, plugin, item, tree=None, modelTableSnapshot=None):
        super(DeleteItemDialog, self).__init__()
        self._plugin = plugin
        self.tree = tree
        self.item = item
        self.modelTableSnapshot = modelTableSnapshot
        # General setup of the dialogtoto
        self.setWindowTitle("Delete Item")
        self.resize(100, 100)
        self._plugin.logger.debug("User want to delete %s " % item)
        # Set up the layout and widgets
        layout = QVBoxLayout(self)

        self._message = QLabel(
            "<b>Are you sure you want to delete the %s  ' %s '  ?</b>" % (str(item.__class__.__name__), item.name))
        layout.addWidget(self._message)
        buttons = QWidget(self)
        buttons_layout = QHBoxLayout(buttons)
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.can_delete_request)
        buttons_layout.addWidget(delete_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)
        layout.addWidget(buttons)

    def can_delete_request(self):
        d = self._plugin.network.send_packet(
            DeleteItem.Query(str(self.item.__class__.__name__), self.item.id, self._plugin.token))
        d.add_callback(self.handle_delete_reply)

    def handle_delete_reply(self, reply: DeleteItem.Reply):
        if bool(reply.error):
            dialog = ErrorMessage(reply.error.name, reply.error, self._plugin)
            dialog.exec_()
        else:
            if isinstance(self.item, Database):
                self.accept()
                return
            elif isinstance(self.item, Project):
                item = self.tree.searchItemInTree(self.item.id, Project)
            elif isinstance(self.item, File):
                item = self.tree.searchItemInTree(self.item.id, File)
            elif isinstance(self.item, Folder):
                item = self.tree.searchItemInTree(self.item.id, Folder)
            self.tree.deleteChild(item)
            self.accept()
