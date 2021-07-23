import binascii
import datetime
import sys
from typing import Optional, List

import ida_loader
import ida_nalt
import idaapi
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant, QModelIndex  # noqa: I202
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QTableWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QGroupBox,
    QGridLayout,
    QTableView, QTableWidget, QMenu, QHeaderView, QAbstractScrollArea)
from functools import partial

from .DetailsFrame import DetailFrame
from .RenameDialog import RenameDialog
from .create import CreateDatabaseDialog, CreateFileDialog
from .treeWidget import ProjectTreeWidget
from ..subdialogs.ChangePermissionDialog import ChangePermissionDialog
from ..subdialogs.CreateFolderDialog import CreateFolderDialog
from ..subdialogs.CreateProjectDialog import CreateProjectDialog
from ..subdialogs.DeleteItemDialog import DeleteItemDialog
from ...shared.commands import *
from ...shared.error import ErrorMessage
from ...shared.models import Project, File

sys.setrecursionlimit(10000)


class DatabaseFrame(QWidget):

    def __init__(self, parent, plugin):
        super(DatabaseFrame, self).__init__()
        self._parent = parent
        self._plugin = plugin
        self.right_layout = None
        self.right_side = parent.right_side
        self._databases: List[Optional[Database]] = list()
        self._databases_group = QGroupBox("Databases", self.right_side)
        self._databases_layout = QVBoxLayout(self._databases_group)
        self._databases_table = self.createTable()
        horizontal_header = self._databases_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        self._databases_table.setSelectionMode(QTableWidget.SingleSelection)
        self._databases_layout.addWidget(self._databases_table)
        self._databases_table.show()
        self._parent._details_frame.right_layout.addWidget(self._databases_group)
        horizontal_header.setSectionResizeMode(QHeaderView.Stretch)
        self._databases_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)

    @property
    def databases(self):
        return self._databases

    @databases.setter
    def databases(self, databases):
        self._databases = databases

    def createTable(self):
        tableView = QTableView()
        self.databaseModelTable = TableDatabaseModel(self._plugin.logger, self._plugin, self, self._parent)
        tableView.setModel(self.databaseModelTable)
        return tableView

    def refresh_database(self, databases: List[Optional[Database]]):
        """Refresh database table"""
        self.databases = databases
        node = self._parent._tree.searchItemInTree(self._parent._tree.project.id, self._parent._tree.project.__class__)
        can_edit = True if node.role in ("Role.Manager", "Role.Analyst") else False
        self.databaseModelTable.refresh_data(databases, can_edit)
        self._databases_table.clicked.connect(self._parent._database_clicked)
        # Add custom context menu for rename and delete
        self._databases_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._databases_table.customContextMenuRequested.connect(self.contextMenuEvent)

    def contextMenuEvent(self, position):
        """
        Handle click on row and display menu :
        Delete and Rename if user is Manager
        """
        self._plugin.logger.debug("Context Menu event with event is  " + str(position) + "\n")
        index: QModelIndex = self._databases_table.indexAt(position)
        db: Database = self.databaseModelTable.getDatabase(index.row())
        self._plugin.logger.debug("Db is " + str(db))
        # Check user permission for rename and delete
        node = self._parent._tree.searchItemInTree(self._parent._tree.project.id, self._parent._tree.project.__class__)
        self._plugin.logger.debug("Role is  " + str(node.role) + "\n")
        can_edit = True if node.role == "Role.Manager" else False
        if can_edit:
            menu = QMenu()
            rename = menu.addAction("Rename")
            rename.triggered.connect(partial(self.rename_database, db))
            rename.setEnabled(True)
            delete = menu.addAction("Delete")
            delete.triggered.connect(partial(self.delete_database, db, index))
            delete.setEnabled(True)
            menu.exec_(self._databases_table.viewport().mapToGlobal(position))

    def delete_database(self, database: Database, index: QModelIndex):
        dialog = DeleteItemDialog(self._plugin, database, modelTableSnapshot=self.databaseModelTable)
        dialog.accepted.connect(partial(self.databaseModelTable.removeDatabase, database))
        dialog.exec_()

    def rename_database(self, database: Database):
        title_dialog = "Rename Database"
        dialog = RenameDialog(self._plugin, title_dialog, database)
        dialog.accepted.connect(partial(self._rename_dialog_accepted, dialog, database))
        dialog.exec_()

    def _rename_dialog_accepted(self, dialog, database: Database):
        new_name, _ = dialog.get_result()
        self.databases[self.databases.index(database)].name = new_name
        self.databaseModelTable.refresh_data(self.databases, True)
        d = self._plugin.network.send_packet(RenameSnapshot.Query(database.id, new_name, self._plugin.token))



class TableDatabaseModel(QAbstractTableModel):

    def __init__(self, logger, plugin, databaseFrame, parent=None):
        super(TableDatabaseModel, self).__init__()
        self.headerdata = ("Name", "Date", "Ticks", "Comments")
        self.data = list()
        self._plugin = plugin
        self._databaseFrame = databaseFrame
        self.logger = logger
        self._parent = parent
        self.can_edit = False

    def getDatabase(self, index):
        return self.data[index][0].data(Qt.UserRole)


    def refresh_data(self, new_data, can_edit):
        self.removeAll()
        self.can_edit = can_edit
        if new_data is not None:
            for database in new_data:
                self.insertRow(database, can_edit)

    def removeAll(self):
        self.beginRemoveRows(QModelIndex(), 0, len(self.data) - 1)
        for i in range(0, len(self.data)):
            self.removeRow(0, QModelIndex())
        self.endRemoveRows()
        self.update(list())

    def removeDatabase(self, database: Database) -> None:
        # remove database from list
        self._databaseFrame.databases.remove(database)
        # recreate table
        self.refresh_data(self._databaseFrame.databases, True)

    def insertRow(self, database: Database, can_edit) -> None:
        tick = str(database.tick) if database.tick != -1 else "<none>"
        self.beginInsertRows(QModelIndex(), 0, 0)
        nameItem = QTableWidgetItem(str(database.name))
        nameItem.setData(Qt.UserRole, database)
        dataItem = QTableWidgetItem(str(database.date))
        dataItem.setData(Qt.UserRole, database)
        tickItem = QTableWidgetItem(str(tick))
        tickItem.setData(Qt.UserRole, database)
        # tickItem.setFlags(tickItem.flags() & ~Qt.ItemIsEditable)
        commentItem = QTableWidgetItem(database.comments)
        commentItem.setData(Qt.UserRole, database)
        # commentItem = QLineEdit()
        # commentItem.setText(database.comments)
        # commentItem.setFlags(commentItem.flags() & ~Qt.ItemIsEditable)
        self.data.append([nameItem, dataItem, tickItem, commentItem])
        self.endInsertRows()

    def update(self, data):
        self.data = data

    def rowCount(self, parent) -> int:
        return len(self.data) if self.data is not None else 0

    def flags(self, index):
        # if index.column == 3:
        if index.isValid():
            if self.getDatabase(index.row()).tick == -1 and self._parent.__class__.__name__ != "SaveDialog":
                return Qt.NoItemFlags | ~Qt.ItemIsEnabled | ~ Qt.ItemIsEditable | ~Qt.ItemIsSelectable
            if index.column() == 3 and self.can_edit:
                return Qt.NoItemFlags | Qt.ItemIsEnabled | Qt.ItemIsEditable | Qt.ItemIsSelectable
            else:
                return Qt.NoItemFlags | Qt.ItemIsEnabled | ~ Qt.ItemIsEditable | Qt.ItemIsSelectable
        else:
            return Qt.NoItemFlags

    def columnCount(self, parent) -> int:
        return len(self.headerdata) if self.headerdata is not None else 0

    def headerData(self, p_int, Qt_Orientation, role=None):
        if role != Qt.DisplayRole:
            return QVariant()
        if Qt_Orientation == Qt.Horizontal:
            return QVariant(self.headerdata[p_int])

    def data(self, index, role):
        row = index.row()
        col = index.column()
        if role == Qt.DisplayRole or role == Qt.EditRole:
            if isinstance(self.data[row][col], str):
                return self.data[row][col]
            return self.data[row][col].text() or ""
        else:
            return QVariant()

    def setData(self, index, value, role=Qt.EditRole):
        if index.isValid():
            row = index.row()
            column = index.column()
            self.data[row][column] = value
            if column == 3 and self.can_edit:
                # send new content of comment
                database = self.getDatabase(row)
                self._plugin.network.send_packet(
                    UpdateComments.Query(database.id, value, self._plugin.token))
            return True
        return False




class TreeFrame(QDialog):
    def __init__(self, plugin):
        super(TreeFrame, self).__init__()
        self.databases = None
        self._file = None
        self._plugin = plugin
        self._plugin.logger.debug("TreeFrame Menu creat  \n")
        self.setWindowTitle("Open from Remote Server")
        icon_path = self._plugin.plugin_resource("download.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(1200, 600)
        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        main_layout = QGridLayout(main)
        layout.addWidget(main)
        self._item_selected = None

        # Tree - left layout
        self._left_side = QWidget(main)
        self._left_layout = QVBoxLayout(self._left_side)
        self._tree = ProjectTreeWidget(self, plugin)

        self._tree.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self._left_layout.addWidget(self._tree)

        main_layout.addWidget(self._left_side, 0, 0)
        main_layout.setColumnStretch(0, 1)

        self.right_side = QWidget(main)
        self._details_frame = DetailFrame(self, self._plugin)
        main_layout.addWidget(self.right_side, 0, 1)
        self._database_frame = DatabaseFrame(self, self._plugin)
        # General buttons - bottom right "stretched" layout
        buttons_widget = QWidget(self)
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.addStretch()
        self._accept_button = QPushButton("Open", buttons_widget)
        self._accept_button.setEnabled(False)
        # Cancel button
        cancel_button = QPushButton("Cancel", buttons_widget)
        # self.reject is a QDialog virtual method
        cancel_button.clicked.connect(self.reject)

        # Place buttons onto UI
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(self._accept_button)
        self._accept_button.clicked.connect(self.accept)
        layout.addWidget(buttons_widget)

        # Ask the server for the list of groups
        d = self._plugin.network.send_packet(ListProject.Query(self._plugin.token))
        d.add_callback(self._projects_listed)
        d.add_errback(self._plugin.logger.exception)


    @property
    def item_selected(self):
        return self._item_selected

    @item_selected.setter
    def item_selected(self, item):
        self._item_selected = item

    def select_project(self, project):
        self._details_frame.populate(project)
        self._file = project

    def _file_created(self, parent, file: File, reply: CreateFile.Reply):
        if bool(reply.error):
            dialog = ErrorMessage("Error permission", reply.error, self._plugin)
            dialog.exec_()
            return
        else:
            file.id = reply.file
            self._tree.insertSubItem(node=parent, item=file)

    def _projects_listed(self, reply: ListProject.Reply):
        self._tree.update_projects(reply)

    def add_project_node(self, project, reply: CreateProject.Reply):
        self._tree.insert_project(project, reply)

    def addDatabase(self, database: Database):
        if self.databases is None:
            self.databases = list()
        self.databases.append(database)
        self._database_frame.refresh_database(self.databases)

    def _database_clicked(self):
        modelIndex = self._database_frame._databases_table.selectedIndexes()[0]
        database = self._database_frame.databaseModelTable.getDatabase(modelIndex.row())
        # [0].data(Qt.UserRole)
        if self.__class__.__name__ == "SaveDialog":
            hash_project = self._file.hash
            hash = ida_nalt.retrieve_input_file_md5()
            # Remove the trailing null byte, if exists
            if hash.endswith(b'\x00'):
                hash = hash[0:-1]
            hash = binascii.hexlify(hash).decode('utf-8')
            if hash_project != hash and hash_project is not None:
                self._accept_button.setEnabled(False)
                self.set_create_database_button(False)
            else:
                self._accept_button.setEnabled(True)
        else:
            self._accept_button.setEnabled(True)


    def get_result(self):
        group = self._file
        project = self._tree._project
        modelIndex = self._database_frame._databases_table.selectedIndexes()[0]
        database = self._database_frame.databaseModelTable.getDatabase(modelIndex.row())
        return group, project, database

    def _create_project_accepted(self, dialog, isRestricted):
        """Called when the project creation dialog is accepted."""
        name = dialog.get_result()
        # Get all the information we need and sent it to the server
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        project = Project(name=name, date=date, restricted=isRestricted)
        d = self._plugin.network.send_packet(CreateProject.Query(project, self._plugin.token))
        d.add_callback(partial(self._project_created, project))
        d.add_errback(self._plugin.logger.exception)

    def _create_project_clicked(self, isRestricted=False):
        dialog = CreateProjectDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_project_accepted, dialog, isRestricted))
        dialog.exec_()

    def _create_folder_clicked(self):
        dialog = CreateFolderDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_folder_accepted, dialog))
        dialog.exec_()

    def _change_permissions(self):
        dialog = ChangePermissionDialog(self._plugin, self.item_selected)
        dialog.exec_()

    def _create_folder_accepted(self, dialog):
        name = dialog.get_result()
        parent = self.item_selected
        folder = Folder(name=name)
        d = self._plugin.network.send_packet(CreateFolder.Query(folder, parent.node, self._plugin.token))
        d.add_callback(partial(self._folder_created, folder, parent))
        d.add_errback(self._plugin.logger.exception)

    def _create_file_clicked(self):
        dialog = CreateFileDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_files_accepted, dialog, self._tree.selectedItems()[0].node))
        dialog.exec_()

    def _delete_item(self):
        dialog = DeleteItemDialog(self._plugin, self._tree.selectedItems()[0].node, tree=self._tree)
        dialog.accepted.connect(partial(self._create_files_accepted, dialog, self._tree.selectedItems()[0].node))
        dialog.exec_()

    def _create_files_accepted(self, dialog, project: Project):
        """Called when the project creation dialog is accepted."""
        name = dialog.get_result()
        # Get all the information we need and sent it to the server
        hash = ida_nalt.retrieve_input_file_md5()
        if hash is not None:
            # Remove the trailing null byte, if exists
            if hash.endswith(b'\x00'):
                hash = hash[0:-1]
            # This decode is safe, because we have an hash in hex format
            hash = binascii.hexlify(hash).decode('utf-8')
        fileName = ida_nalt.get_root_filename()
        file = None
        ftype = ida_loader.get_file_type_name()
        info = idaapi.get_inf_structure()
        # is_32bit = info.is_32bit()
        is_64bit = info.is_64bit()
        date_format = "%Y/%m/%d %H:%M"

        date = datetime.datetime.now().strftime(date_format)
        parent = self.item_selected
        if isinstance(parent.node, Project):
            project = parent.node
            self._plugin.logger.debug("Parent is  project  %s, id: %d " % (project.name, project.id))
            file = File(project_id=project.id, folder_id=None, name=name, hash=hash, file=fileName, ftype=ftype,
                        date=date, is_64bit=is_64bit)
        elif isinstance(parent.node, Folder):
            folder = parent.node
            self._plugin.logger.debug("Parent is  folder %s, id: %d" % (folder.name, folder.id))
            file = File(folder_id=folder.id, project_id=None, name=name, hash=hash, file=fileName, ftype=ftype,
                        date=date, is_64bit=is_64bit)

        if hash is None:
            file.ftype = None
            file.is_64bit = None
        if file is None:
            self._plugin.logger.exception("Error occured file is None")
        d = self._plugin.network.send_packet(
            CreateFile.Query(file, parent.node.id, parent.node.__class__.__name__, self._plugin.token))
        d.add_callback(partial(self._file_created, parent, file))
        d.add_errback(self._plugin.logger.exception)

    def _create_database_clicked(self):
        """Called when the create database button is clicked."""
        dialog = CreateDatabaseDialog(self._plugin)
        dialog.accepted.connect(
            partial(self._create_database_accepted, dialog)
        )
        dialog.exec_()

    def _project_created(self, project, reply: CreateProject.Reply):
        """Update list of projects when the create project reply is received.
        if error in packet display a message error """
        error = reply.project
        if error is not None: self.add_project_node(project, reply)

    def _rename_clicked(self):
        item = self.item_selected
        if isinstance(item.node, Project):
            title_dialog = "Rename project"
        elif isinstance(item.node, File):
            title_dialog = "Rename file"
        else:
            title_dialog = "Rename project"
        dialog = RenameDialog(self._plugin, title_dialog, item)
        dialog.accepted.connect(partial(self._rename_dialog_accepted, dialog, item))
        dialog.exec_()


    def _rename_dialog_accepted(self, dialog, node):
        new_name, item = dialog.get_result()
        # Send the packet to the server with the new name
        if isinstance(node.node, Project):
            d = self._plugin.network.send_packet(RenameProject.Query(item.id, new_name, self._plugin.token))
        elif isinstance(node.node, File):
            d = self._plugin.network.send_packet(RenameFile.Query(item.id, new_name, self._plugin.token))
        elif isinstance(node.node, Folder):
            d = self._plugin.network.send_packet(RenameFolder.Query(item.id, new_name, self._plugin.token))
        d.add_callback(partial(self._item_renamed, node, new_name))
        d.add_errback(self._plugin.logger.exception)

    def _item_renamed(self, node, new_name, reply):
        self._renamed = reply.renamed
        if self._renamed:
            node.setText(0, new_name)
        else:
            self._plugin.logger.debug("Create project dialog")
            if reply.error:
                dialog = ErrorMessage("Error permission", reply.error, self._plugin)
                dialog.exec_()
                return

    def _folder_created(self, folder, parent, reply: CreateFolder.Reply):
        """Update the treeView with the new folder"""
        error = reply.error
        if error is None:
            folder.id = reply.folder_id
            self._tree.insert_folder(folder, parent)
        else:
            self._plugin.logger.exception("Error folder created")
