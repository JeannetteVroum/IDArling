# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import binascii
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import datetime
import logging
import platform

import ida_loader
import ida_nalt
import idaapi
from PyQt5.QtCore import Qt  # noqa: I202
from PyQt5.QtWidgets import (
    QColorDialog,
    QComboBox,
    QFormLayout,
    QHeaderView,
    QMessageBox,
    QCheckBox,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget)
from functools import partial

from .project.TreeView import TreeFrame
from .project.create import *
from .subdialogs.ServerInfoDialog import ServerInfoDialog
from ..shared.commands import (
    CreateDatabase,
    RenameFile,
    ListProject,
    UpdateUserColor,
    ListChildren)
from ..shared.error import ErrorMessage
from ..shared.models import Database


class OpenDialog(QDialog):
    """This dialog is shown to user to select which remote database to load."""

    def _groups_listed(self, reply: ListProject.Reply):
        """Called when the groups list is received."""
        self._projects = reply.projects
        # self._projects = sorted(reply.groups, key=lambda x: x.date, reverse=True) # sort groups by reverse date
        self._refresh_groups()

    def _refresh_groups(self):
        """Refreshes the groups table."""
        self._groups_table.setRowCount(len(self._projects))
        self._groups_table.setColumnCount(1)
        for i, group in enumerate(self._projects):
            item = QTableWidgetItem(group.name)
            item.setData(Qt.UserRole, group)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._groups_table.setItem(i, 0, item)

    def _projects_listed(self, reply: ListChildren.Reply):
        self._plugin.logger.debug("OpenDialog._projects_listed()")
        """Called when the projects list is received."""
        # self._files = sorted(reply.projects, key=lambda x: x.name) # sort project by name
        # self._files = sorted(reply.projects, key=lambda x: x.date, reverse=True) # sort project by reverse date
        self._files = reply.files
        self._refresh_projects()

    def _refresh_projects(self):
        self._plugin.logger.debug("OpenDialog._refresh_projects()")
        """Refreshes the projects table."""
        self._projects_table.setRowCount(len(self._files))
        for i, project in enumerate(self._files):
            item = QTableWidgetItem(project.name)
            item.setData(Qt.UserRole, project)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._projects_table.setItem(i, 0, item)

    def _databases_listed(self, reply):
        """Called when the databases list is received."""
        self._databases = self.sort_databases(reply.databases)
        self._refresh_databases()

    def _refresh_databases(self):
        """Refreshes the table of databases."""

        def create_item(text, database):
            item = QTableWidgetItem(str(text))
            item.setData(Qt.UserRole, database)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if database.tick == -1:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            return item

        self._databases_table.setRowCount(len(self._databases))
        for i, database in enumerate(self._databases):
            self._databases_table.setItem(
                i, 0, create_item(database.name, database)
            )
            self._databases_table.setItem(
                i, 1, create_item(database.date, database)
            )
            tick = str(database.tick) if database.tick != -1 else "<none>"
            self._databases_table.setItem(i, 2, create_item(tick, database))

    def _database_double_clicked(self):
        project_type = self._projects_table.selectedItems()[0].data(Qt.UserRole).ftype
        # For now we are only detecting some bad matching between IDA architecture
        # and the disassembled binary's architecture but we would need to
        # actually save a project architecture (32-bit or 64-bit) to support all
        # cases
        # E.g. below we support "Portable executable for 80386 (PE)" vs
        # "Portable executable for AMD64 (PE)"
        if (platform.architecture()[0] == "64bit" and "80386" in project_type) \
                or (platform.architecture()[0] == "32bit" and "AMD64" in project_type):
            QMessageBox.about(self, "IDArling Error", "Wrong architecture!\n"
                                                      "You must use the right version of IDA/IDA64,")
            return
        self.accept()

    def _rename_project_dialog_accepted(self, dialog):
        group = self._groups_table.selectedItems()[0].data(Qt.UserRole).name
        old_name = self._projects_table.selectedItems()[0].data(Qt.UserRole).name
        new_name = dialog.get_result()

        self._plugin.logger.info("Request to rename to %s to %s in group: %s" % (old_name, new_name, group))
        # Send the packet to the server with the new name
        d = self._plugin.network.send_packet(RenameFile.Query(group, old_name, new_name))
        d.add_callback(self._project_renamed)
        d.add_errback(self._plugin.logger.exception)

    def _project_renamed(self, reply):
        self._renamed = reply.renamed
        if self._renamed:
            self._files = self.sort_projects(reply.projects)
            self._refresh_projects()
        else:
            self._plugin.logger.debug("Create project dialog")
            QMessageBox.about(self, "IDArling Error", "Unable to rename.\n"
                                                      "Likely more than one client connected?")

    def get_result(self):
        """Get the project and database selected by the user."""
        group = self._groups_table.selectedItems()[0].data(Qt.UserRole)
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        database = self._databases_table.selectedItems()[0].data(Qt.UserRole)
        return group, project, database

    # XXX - Make x.name configurable based on clicking on columns
    def sort_projects(self, projects):
        # return sorted(projects, key=lambda x: x.date, reverse=True) # sort project by reverse date
        return sorted(projects, key=lambda x: x.name)

    # XXX - Make x.date configurable based on clicking on columns
    def sort_databases(self, databases):
        return sorted(databases, key=lambda x: x.date, reverse=True)  # sort databases by reverse date


class SaveDialog(TreeFrame):
    """
    This save dialog is shown to user to select which remote database to save. We
    extend the open dialog to reuse most of the UI setup code.
    """

    def __init__(self, plugin):
        super(SaveDialog, self).__init__(plugin)
        self.item_selected = None
        self._action = "SaveDialog"
        # General setup of the dialog
        self.setWindowTitle("Save to Remote Server")
        icon_path = self._plugin.plugin_resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))

        # Change the accept button text
        self._accept_button.setText("Save")
        self.create_database_button = QPushButton("Create database", self.right_side)
        self.create_database_button.clicked.connect(self._create_database_clicked)
        self.right_layout.addWidget(self.create_database_button)
        self.create_database_button.setEnabled(False)

    def set_create_database_button(self, state: bool):
        """Set status of create database
        Enable when a idb is open and File is selected"""
        self.create_database_button.setEnabled(state)

    """
    def set_create_project_button(self, state: bool):
        self.create_file_button.setEnabled(state)

    def set_create_folder_button(self, state: bool):
        self._create_folder_button.setEnabled(state)
    """
    # XXX - not needed?
    def _refresh_groups(self):
        super(SaveDialog, self)._refresh_groups()
        for row in range(self._groups_table.rowCount()):
            item = self._groups_table.item(row, 0)
            group = item.data(Qt.UserRole)
            pass

    def _create_database_accepted(self, dialog):
        """Called when the database creation dialog is accepted."""
        file = self._tree.selectedItems()[0].node
        name = dialog.get_result()
        # Get all the information we need and sent it to the server
        date_format = "%Y/%m/%d %H:%M"
        is_64bit = None
        fileName = None
        hash = None
        ftype = None
        if file.hash is None and file.is_64bit is None:
            # check hash current db and is 64 bit or not
            info = idaapi.get_inf_structure()
            is_64bit = info.is_64bit()
            fileName = ida_nalt.get_root_filename()
            hash = ida_nalt.retrieve_input_file_md5()
            # Remove the trailing null byte, if exists
            if hash.endswith(b'\x00'):
                hash = hash[0:-1]
            hash = binascii.hexlify(hash).decode('utf-8')
            ftype = ida_loader.get_file_type_name()
            self._plugin.logger.debug("Hash is none and 64 bit too")
        date = datetime.datetime.now().strftime(date_format)
        database = Database(name=name, date=date, file_id=file.id, tick=-1)
        d = self._plugin.network.send_packet(
            CreateDatabase.Query(database, is_64bit, fileName, hash, ftype, self._plugin.token))
        d.add_callback(partial(self._database_created, database))
        d.add_errback(self._plugin.logger.exception)

    def _database_created(self, database, reply: CreateDatabase.Reply):
        """Called when the new database reply is received."""
        if reply.error:
            dialog = ErrorMessage("Authorization", reply.error, self._plugin.logger)
            dialog.exec_()
        else:
            database.id = reply.database_id
            self._refresh_databases(database)

    def _refresh_databases(self, database: Database):
        self.addDatabase(database)


class SettingsDialog(QDialog):
    """
    The dialog allowing an user to configure the plugin. It has multiple tabs
    used to group the settings by category (general, network, etc.).
    """

    def __init__(self, plugin):
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing settings dialog")
        self.setWindowTitle("Settings")
        icon_path = self._plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        window_widget = QWidget(self)
        window_layout = QVBoxLayout(window_widget)
        tabs = QTabWidget(window_widget)
        window_layout.addWidget(tabs)

        # "General Settings" tab
        tab = QWidget(tabs)
        layout = QFormLayout(tab)
        layout.setFormAlignment(Qt.AlignVCenter)
        tabs.addTab(tab, "General Settings")

        user_widget = QWidget(tab)
        user_layout = QHBoxLayout(user_widget)
        layout.addRow(user_widget)

        # User color
        self._color_button = QPushButton("")
        self._color_button.setFixedSize(50, 30)

        def color_button_activated(_):
            self._set_color(qt_color=QColorDialog.getColor().rgb())

        self._color = self._plugin.config["user"]["color"]
        self._set_color(ida_color=self._color)
        self._color_button.clicked.connect(color_button_activated)
        user_layout.addWidget(self._color_button)

        text = "Disable all user cursors"
        self._disable_all_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_all_cursors_checkbox)
        navbar_checked = not self._plugin.config["cursors"]["navbar"]
        funcs_checked = not self._plugin.config["cursors"]["funcs"]
        disasm_checked = not self._plugin.config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        def state_changed(state):
            enabled = state == Qt.Unchecked
            self._disable_navbar_cursors_checkbox.setChecked(not enabled)
            self._disable_navbar_cursors_checkbox.setEnabled(enabled)
            self._disable_funcs_cursors_checkbox.setChecked(not enabled)
            self._disable_funcs_cursors_checkbox.setEnabled(enabled)
            self._disable_disasm_cursors_checkbox.setChecked(not enabled)
            self._disable_disasm_cursors_checkbox.setEnabled(enabled)

        self._disable_all_cursors_checkbox.stateChanged.connect(state_changed)

        style_sheet = """QCheckBox{ margin-left: 20px; }"""

        text = "Disable navigation bar user cursors"
        self._disable_navbar_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_navbar_cursors_checkbox)
        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_navbar_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable functions window user cursors"
        self._disable_funcs_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_funcs_cursors_checkbox)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable disassembly view user cursors"
        self._disable_disasm_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_disasm_cursors_checkbox)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Allow other users to send notifications"
        self._notifications_checkbox = QCheckBox(text)
        layout.addRow(self._notifications_checkbox)
        checked = self._plugin.config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        # Log level
        debug_level_label = QLabel("Logging level: ")
        self._debug_level_combo_box = QComboBox()
        self._debug_level_combo_box.addItem("CRITICAL", logging.CRITICAL)
        self._debug_level_combo_box.addItem("ERROR", logging.ERROR)
        self._debug_level_combo_box.addItem("WARNING", logging.WARNING)
        self._debug_level_combo_box.addItem("INFO", logging.INFO)
        self._debug_level_combo_box.addItem("DEBUG", logging.DEBUG)
        self._debug_level_combo_box.addItem("TRACE", logging.TRACE)
        level = self._plugin.config["level"]
        index = self._debug_level_combo_box.findData(level)
        self._debug_level_combo_box.setCurrentIndex(index)
        layout.addRow(debug_level_label, self._debug_level_combo_box)

        # "Network Settings" tab
        tab = QWidget(tabs)
        layout = QVBoxLayout(tab)
        tab.setLayout(layout)
        tabs.addTab(tab, "Network Settings")

        top_widget = QWidget(tab)
        layout.addWidget(top_widget)
        top_layout = QHBoxLayout(top_widget)

        self._servers = list(self._plugin.config["servers"])
        self._servers_table = QTableWidget(len(self._servers), 3, self)
        top_layout.addWidget(self._servers_table)
        for i, server in enumerate(self._servers):
            # Server host and port
            item = QTableWidgetItem("%s:%d" % (server["host"], server["port"]))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            # XXX - This prevented editing a server entry for your current 
            # server because the row cannot be selected properly with 
            # SingleSelection option selected
            # if self._plugin.network.server == server:
            #    item.setFlags((item.flags() & ~Qt.ItemIsSelectable))
            self._servers_table.setItem(i, 0, item)

            # Server has SSL enabled?
            ssl_checkbox = QTableWidgetItem()
            state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
            ssl_checkbox.setCheckState(state)
            ssl_checkbox.setFlags((ssl_checkbox.flags() & ~Qt.ItemIsEditable))
            ssl_checkbox.setFlags((ssl_checkbox.flags() & ~Qt.ItemIsUserCheckable))
            self._servers_table.setItem(i, 1, ssl_checkbox)

            # Auto-connect enabled?
            auto_checkbox = QTableWidgetItem()
            state = Qt.Unchecked if not server["auto_connect"] else Qt.Checked
            auto_checkbox.setCheckState(state)
            auto_checkbox.setFlags((auto_checkbox.flags() & ~Qt.ItemIsEditable))
            auto_checkbox.setFlags((auto_checkbox.flags() & ~Qt.ItemIsUserCheckable))
            self._servers_table.setItem(i, 2, auto_checkbox)

        self._servers_table.setHorizontalHeaderLabels(("Servers", "SSL",
                                                       "Auto"))
        horizontal_header = self._servers_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, QHeaderView.Stretch)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        horizontal_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._servers_table.verticalHeader().setVisible(False)
        self._servers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._servers_table.setSelectionMode(QTableWidget.SingleSelection)
        self._servers_table.itemClicked.connect(self._server_clicked)
        self._servers_table.itemDoubleClicked.connect(
            self._server_double_clicked
        )
        self._servers_table.setMaximumHeight(100)

        buttons_widget = QWidget(top_widget)
        buttons_layout = QVBoxLayout(buttons_widget)
        top_layout.addWidget(buttons_widget)

        # Add server button
        self._add_button = QPushButton("Add Server")
        self._add_button.clicked.connect(self._add_button_clicked)
        buttons_layout.addWidget(self._add_button)

        # Edit server button
        self._edit_button = QPushButton("Edit Server")
        self._edit_button.setEnabled(False)
        self._edit_button.clicked.connect(self._edit_button_clicked)
        buttons_layout.addWidget(self._edit_button)

        # Delete server button
        self._delete_button = QPushButton("Delete Server")
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_button_clicked)
        buttons_layout.addWidget(self._delete_button)

        bottom_widget = QWidget(tab)
        bottom_layout = QFormLayout(bottom_widget)
        layout.addWidget(bottom_widget)

        # TCP Keep-Alive settings
        keep_cnt_label = QLabel("Keep-Alive Count: ")
        self._keep_cnt_spin_box = QSpinBox(bottom_widget)
        self._keep_cnt_spin_box.setRange(0, 86400)
        self._keep_cnt_spin_box.setValue(self._plugin.config["keep"]["cnt"])
        self._keep_cnt_spin_box.setSuffix(" packets")
        bottom_layout.addRow(keep_cnt_label, self._keep_cnt_spin_box)

        keep_intvl_label = QLabel("Keep-Alive Interval: ")
        self._keep_intvl_spin_box = QSpinBox(bottom_widget)
        self._keep_intvl_spin_box.setRange(0, 86400)
        self._keep_intvl_spin_box.setValue(
            self._plugin.config["keep"]["intvl"]
        )
        self._keep_intvl_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_intvl_label, self._keep_intvl_spin_box)

        keep_idle_label = QLabel("Keep-Alive Idle: ")
        self._keep_idle_spin_box = QSpinBox(bottom_widget)
        self._keep_idle_spin_box.setRange(0, 86400)
        self._keep_idle_spin_box.setValue(self._plugin.config["keep"]["idle"])
        self._keep_idle_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_idle_label, self._keep_idle_spin_box)

        # Buttons commons to all tabs
        actions_widget = QWidget(self)
        actions_layout = QHBoxLayout(actions_widget)

        # Cancel = do not save the changes and close the dialog
        def cancel(_):
            self.reject()

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(cancel)
        actions_layout.addWidget(cancel_button)

        # Reset = reset all settings from all tabs to default values
        reset_button = QPushButton("Reset")
        reset_button.clicked.connect(self._reset)
        actions_layout.addWidget(reset_button)

        # Save = save the changes and close the dialog
        def save(_):
            self._commit()
            self.accept()

        save_button = QPushButton("Save")
        save_button.clicked.connect(save)
        actions_layout.addWidget(save_button)
        window_layout.addWidget(actions_widget)

        # Do not allow the user to resize the dialog
        self.setFixedSize(
            window_widget.sizeHint().width(), window_widget.sizeHint().height()
        )

    def _set_color(self, ida_color=None, qt_color=None):
        """Sets the color of the user color button."""
        # IDA represents colors as 0xBBGGRR
        if ida_color is not None:
            r = ida_color & 255
            g = (ida_color >> 8) & 255
            b = (ida_color >> 16) & 255

        # Qt represents colors as 0xRRGGBB
        if qt_color is not None:
            r = (qt_color >> 16) & 255
            g = (qt_color >> 8) & 255
            b = qt_color & 255

        ida_color = r | g << 8 | b << 16
        qt_color = r << 16 | g << 8 | b

        # Set the stylesheet of the button
        css = "QPushButton {background-color: #%06x; color: #%06x;}"
        self._color_button.setStyleSheet(css % (qt_color, qt_color))
        self._color = ida_color

    def _server_clicked(self, _):
        self._edit_button.setEnabled(True)
        self._delete_button.setEnabled(True)

    def _server_double_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        # If not the current server, connect to it
        if (
                not self._plugin.network.connected
                or self._plugin.network.server != server
        ):
            self._plugin.network.stop_server()
            self._plugin.network.connect(server)
        self.accept()

    def _add_button_clicked(self, _):
        dialog = ServerInfoDialog(self._plugin, "Add server")
        dialog.accepted.connect(partial(self._add_dialog_accepted, dialog))
        dialog.exec_()

    def _edit_button_clicked(self, _):
        selected = self._servers_table.selectedItems()
        if len(selected) == 0:
            self._plugin.logger.warning("No server selected")
            return
        item = selected[0]
        server = item.data(Qt.UserRole)
        dialog = ServerInfoDialog(self._plugin, "Edit server", server)
        dialog.accepted.connect(partial(self._edit_dialog_accepted, dialog))
        dialog.exec_()

    def _delete_button_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        self._servers.remove(server)
        self._plugin.save_config()
        self._servers_table.removeRow(item.row())
        self.update()

    def _add_dialog_accepted(self, dialog):
        """Called when the dialog to add a server is accepted."""
        server = dialog.get_result()
        self._servers.append(server)
        row_count = self._servers_table.rowCount()
        self._servers_table.insertRow(row_count)

        new_server = QTableWidgetItem(
            "%s:%d" % (server["host"], server["port"])
        )
        new_server.setData(Qt.UserRole, server)
        new_server.setFlags(new_server.flags() & ~Qt.ItemIsEditable)
        self._servers_table.setItem(row_count, 0, new_server)

        new_checkbox = QTableWidgetItem()
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        new_checkbox.setCheckState(state)
        new_checkbox.setFlags((new_checkbox.flags() & ~Qt.ItemIsEditable))
        new_checkbox.setFlags(new_checkbox.flags() & ~Qt.ItemIsUserCheckable)
        self._servers_table.setItem(row_count, 1, new_checkbox)
        self.update()

    def _edit_dialog_accepted(self, dialog):
        """Called when the dialog to edit a server is accepted."""
        server = dialog.get_result()
        item = self._servers_table.selectedItems()[0]
        self._servers[item.row()] = server

        item.setText("%s:%d" % (server["host"], server["port"]))
        item.setData(Qt.UserRole, server)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        checkbox = self._servers_table.item(item.row(), 1)
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        checkbox.setCheckState(state)
        self.update()

    def _reset(self, _):
        """Resets all the form elements to their default value."""
        config = self._plugin.default_config()

        self._name_line_edit.setText(config["user"]["name"])
        self._set_color(ida_color=config["user"]["color"])

        navbar_checked = not config["cursors"]["navbar"]
        funcs_checked = not config["cursors"]["funcs"]
        disasm_checked = not config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)

        checked = config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        index = self._debug_level_combo_box.findData(config["level"])
        self._debug_level_combo_box.setCurrentIndex(index)

        del self._servers[:]
        self._servers_table.clearContents()
        self._keep_cnt_spin_box.setValue(config["keep"]["cnt"])
        self._keep_intvl_spin_box.setValue(config["keep"]["intvl"])
        self._keep_idle_spin_box.setValue(config["keep"]["idle"])

    def _commit(self):
        """Commits all the changes made to the form elements."""

        if self._plugin.config["user"]["color"] != self._color:
            name = self._plugin.config["user"]["name"]
            old_color = self._plugin.config["user"]["color"]
            packet = UpdateUserColor(name, old_color, self._color)
            self._plugin.network.send_packet(packet)
            self._plugin.config["user"]["color"] = self._color
            self._plugin.interface.widget.refresh()

        all_ = self._disable_all_cursors_checkbox.isChecked()
        checked = self._disable_navbar_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["navbar"] = not all_ and not checked
        checked = self._disable_funcs_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["funcs"] = not all_ and not checked
        checked = self._disable_disasm_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["disasm"] = not all_ and not checked

        checked = self._notifications_checkbox.isChecked()
        self._plugin.config["user"]["notifications"] = checked

        index = self._debug_level_combo_box.currentIndex()
        level = self._debug_level_combo_box.itemData(index)
        self._plugin.logger.setLevel(level)
        self._plugin.config["level"] = level

        self._plugin.config["servers"] = self._servers
        cnt = self._keep_cnt_spin_box.value()
        self._plugin.config["keep"]["cnt"] = cnt
        intvl = self._keep_intvl_spin_box.value()
        self._plugin.config["keep"]["intvl"] = intvl
        idle = self._keep_idle_spin_box.value()
        self._plugin.config["keep"]["idle"] = idle
        if self._plugin.network.client:
            self._plugin.network.client.set_keep_alive(cnt, intvl, idle)

        self._plugin.save_config()
