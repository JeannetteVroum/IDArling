from PyQt5 import QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetItem, QWidget, QVBoxLayout, QComboBox, QHeaderView, \
    QPushButton
from functools import partial

from idarling.shared.commands import ListUsersProject, ChangedRole, RemoveAllUserAffecteds
from idarling.shared.models import Affected


class ChangePermissionDialog(QDialog):
    "The dialog shown when an user wants to create a Folder."""

    def __init__(self, plugin, item_selected):
        super(ChangePermissionDialog, self).__init__()
        self._plugin = plugin
        self._plugin.logger.debug("Item is %s " % item_selected.node.id)
        self.project_id = item_selected.node.id
        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        layout.addWidget(main)
        # General setup of the dialogtoto
        self.setWindowTitle("Change permissions")
        # Users tables
        self._user_table = UsersFrame(self, self._plugin)
        layout.addWidget(self._user_table)
        d = self._plugin.network.send_packet(ListUsersProject.Query(item_selected.node.id, self._plugin.token))
        d.add_callback(partial(self.create_table))
        d.add_errback(self._plugin.logger.exception)
        self.remove_all_users_button = QPushButton("Remove all")
        self.remove_all_users_button.clicked.connect(self.remove_all_user)
        layout.addWidget(self.remove_all_users_button)


    def remove_all_user(self, _):
        d = self._plugin.network.send_packet(RemoveAllUserAffecteds.Query(self.project_id, self._plugin.token))
        d.add_callback(self.change_role)
        d.add_errback(self._plugin.logger.exception)

    def create_table(self, reply: ListUsersProject.Reply):
        self._user_table.insert_user_list(reply)

    def change_role(self, reply: ListUsersProject.Reply):
        if reply.error is not None:
            self._plugin.logger.exception("Exception %s " % reply.error)
        else:
            d = self._plugin.network.send_packet(ListUsersProject.Query(self.project_id, self._plugin.token))
            d.add_callback(partial(self.create_table))
            d.add_errback(self._plugin.logger.exception)


class UsersFrame(QTableWidget):
    def __init__(self, parent, plugin):
        super(UsersFrame, self).__init__()
        self._parent = parent
        self._plugin = plugin
        icon_path = self._plugin.plugin_resource("circle-48.png")
        self._activeIcon = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("circle-48-black.png")
        self._inactiveIcon = QIcon(icon_path)
        self.setColumnCount(3)
        self.setRowCount(7)
        labels = ("Users", "Role", "active")
        self.setHorizontalHeaderLabels(labels)
        horizontal_header = self.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)

    def insert_user_list(self, reply: ListUsersProject.Reply):
        user_len = len(reply.permissions)
        self.setRowCount(user_len)
        for i in range(user_len):
            username = reply.permissions[i][0]
            comboRole = ComboRole(self._parent, self._plugin, reply.permissions[i][1], username)
            self._plugin.logger.debug("Combo role permission is %s " % reply.permissions[i][1])
            active = reply.permissions[i][2]
            self.insertUser(username, comboRole, active, i)
        self.resizeColumnsToContents()
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def insertUser(self, username: str, comboRole: object, active: bool, position: int):
        usernameItem = QTableWidgetItem(username)
        activeItem = QTableWidgetItem()
        activeItem.setData(Qt.DecorationRole, self._activeIcon) if active else activeItem.setData(Qt.DecorationRole,
                                                                                                  self._inactiveIcon)
        self.setItem(position, 0, usernameItem)
        self.setCellWidget(position, 1, comboRole)
        self.setItem(position, 2, activeItem)


class ComboRole(QComboBox):

    def __init__(self, parent, plugin, current_role, username):
        super(ComboRole, self).__init__()
        self._parent = parent
        self._plugin = plugin
        current_role = current_role.split('.')[1]
        self.username = username
        for role in Affected.Role:
            if role.name != "Admin" and current_role != "Admin":
                self.addItem(role.name)
        if current_role == "Admin":
            self.setDisabled(True)
        self.setCurrentText(current_role)
        self.currentIndexChanged.connect(self.role_changed)

    def role_changed(self, i):
        # get current role
        new_role = self.currentText()
        username = self.username
        d = self._plugin.network.send_packet(
            ChangedRole.Query(self._parent.project_id, username, new_role, self._plugin.token))
        d.add_errback(self._plugin.logger.exception)
        d.add_callback(self.errback)

    def errback(self, reply):
        self._plugin.logger.exception(reply.error)

    def wheelEvent(self, e: QtGui.QWheelEvent) -> None:
        """Ignore mouse wheel event"""
        {

        }
