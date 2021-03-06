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
import binascii
from typing import Optional

import ida_nalt
from PyQt5.QtCore import Qt  # noqa: I202
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QTreeWidgetItem, QTreeWidget, QMenu
from functools import partial

from idarling.shared.commands import ListProject, CreateProject, ListDatabases, ListChildren
from idarling.shared.error import ErrorMessage
from idarling.shared.models import Project, Folder, File


class TreeItemWrapper(QTreeWidgetItem):
    """Adding attributes to tree nodes"""

    def __init__(self, node, role=None):
        super(TreeItemWrapper, self).__init__()
        self.node = node
        self.role = role


class ProjectTreeWidget(QTreeWidget):
    def __init__(self, parent, plugin):
        super(ProjectTreeWidget, self).__init__()
        self._parent = parent

        self._project: Optional[Project] = None
        self._file = None
        self._plugin = plugin
        self._plugin.logger.debug("ProjectTreeWidget create")

        self._projects = None
        self.setColumnCount(1)
        self.setHeaderLabels(['Remote Projects'])
        self.setContextMenuPolicy(Qt.CustomContextMenu)  # handle custom right click
        self.customContextMenuRequested.connect(self.contextMenuEvent)
        self._plugin.logger.debug("Create server root")

        # self.itemDoubleClicked.connect(self.itemDoubleClickedEvent)
        self.itemClicked.connect(self.itemDoubleClickedEvent)
        self.itemClicked.connect(self.itemSelected)
        icon_path = self._plugin.plugin_resource("dir.ico")
        self.diricon = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("prj.ico")
        self.prjicon = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("32bits.png")
        self.icon32bit = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("64bits.png")
        self.icon64bit = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("reader.png")
        self.readericon = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("analyst.png")
        self.analysticon = QIcon(icon_path)
        icon_path = self._plugin.plugin_resource("manager.png")
        self.managericon = QIcon(icon_path)
        self.addTopLevelItem(QTreeWidgetItem(None, ["Server root"]))


    @property
    def project(self) -> Optional[Project]:
        return self._project

    @project.setter
    def project(self, project: Project):
        self._project = project

    def get_project_parent(self, item: TreeItemWrapper) -> Project:
        """ Return the project of current Item"""
        while isinstance(item, TreeItemWrapper):
            if isinstance(item.node, Project):
                return item.node
            item = item.parent()

    def contextMenuEvent(self, position):
        """Display context menu (Create Project/Folder/File) in Save to Remote Server menu"""

        def get_role(item):
            """Return the role affected for current item"""
            while isinstance(item, TreeItemWrapper):
                if isinstance(item.node, Project):
                    return item.role
                item = item.parent()
        node = self.itemAt(position)
        node.setSelected(True)
        # node = self.currentItem()
        if not node:
            return
        menu = QMenu()
        if isinstance(node, TreeItemWrapper):
            role = get_role(node)
            self._project = self.get_project_parent(node)
            self._parent.item_selected = node
            if isinstance(node.node, Project) and role == "Role.Manager":
                change_permission = menu.addAction("Change permissions")
                change_permission.triggered.connect(self._parent._change_permissions)
                change_permission.setEnabled(True)
            if (isinstance(node.node, Project) or isinstance(node.node, Folder)) and role in ("Role.Manager",
                                                                                              "Role.Analyst"):
                create_file = menu.addAction("New File")
                create_file.triggered.connect(self._parent._create_file_clicked)
                create_file.setEnabled(True)
                create_folder = menu.addAction("New Folder")
                create_folder.triggered.connect(self._parent._create_folder_clicked)
                create_folder.setEnabled(True)
            if (isinstance(node.node, Project) or isinstance(node.node, Folder)) and role == "Role.Manager":
                rename_item = menu.addAction("Rename")
                rename_item.triggered.connect(self._parent._rename_clicked)
            if role in ("Role.Manager", "Role.Admin"):
                delete_item = menu.addAction("Delete")
                delete_item.triggered.connect(self._parent._delete_item)
        else:
            create_project = menu.addAction("New Project")
            create_project.setEnabled(True)
            create_project.triggered.connect(self._parent._create_project_clicked)
            create_project_restricted = menu.addAction("New Restricted Project")
            create_project_restricted.triggered.connect(partial(self._parent._create_project_clicked, True))
            create_project_restricted.setEnabled(True)
        self._parent.item_selected = node
        menu.exec_(self.viewport().mapToGlobal(position))
    def update_projects(self, reply: ListProject.Reply):
        """Update TreeView with Project"""

        def search_in_permissions_list(id_project, lst):
            """Search in list permissions the current project and return icon corresponding"""
            for permission in lst:
                if permission["id_project"] == id_project:
                    role = permission["role"]
                    if "Analyst" in role:
                        return self.analysticon
                    elif "Reader" in role:
                        return self.readericon
                    elif "Manager" in role:
                        return self.managericon

        def get_role(id_project, lst):
            for permission in lst:
                if permission["id_project"] == id_project:
                    role = permission["role"]
                    return role

        self._projects = reply.projects
        root = self.topLevelItem(0)
        self._plugin.logger.debug("root Treeview is " + str(root))
        for project in self._projects:
            self._plugin.logger.debug("Insert item"  +str(project))

            node = TreeItemWrapper(project, get_role(project.id, reply.permissions))
            node.setText(0, project.name)
            node.setIcon(0, search_in_permissions_list(project.id, reply.permissions))
            root.addChild(node)

    def insert_project(self, project, reply: CreateProject.Reply):
        """
        Insert a project node in TreeView
        :param reply:
        :return:
        """
        root = self.topLevelItem(0)
        project = project
        project.id = reply.project.id
        node = TreeItemWrapper(project)
        node.setText(0, project.name)
        node.setIcon(0, self.managericon)
        node.role = "Role.Manager"
        root.addChild(node)
        # update projects list
        self._projects.append(project)
        self._project = project
        # self._parent.set_create_folder_button(True)
        self.clearSelection()
        node.setSelected(True)
        # self.itemSelected(node, None)

    def insert_folder(self, folder: Folder, parent) -> None:
        """
        Insert folder item in the treeView
        :param folder: Folder
        :param parent: Node
        """
        node = TreeItemWrapper(folder)
        node.setText(0, folder.name)
        node.setIcon(0, self.diricon)
        node.role = parent.role
        parent.addChild(node)
        self.clearSelection()
        node.setSelected(True)
        # self.itemSelected(node, None)

    def itemSelected(self, item, column):
        """
        Handler for selected item
        save the current state of item selected
        :rtype: None
        """
        def get_project(item):
            """Return the project of current item"""
            current = item
            while isinstance(current, TreeItemWrapper):
                if isinstance(current.node, Project):
                    return current.role
                current = current.parent()

        if self._parent.__class__.__name__ == "SaveDialog":
            if isinstance(item, TreeItemWrapper):
                role = get_project(item)
                self._project = self.get_project_parent(item)
                if isinstance(item.node, Project) or isinstance(item.node, Folder):
                    self._parent.set_create_database_button(False)
                    # remove databases in table
                    self._parent.databases = None
                    self._parent._database_frame.refresh_database(self._parent.databases)
                    self._parent._details_frame.clean()
                elif isinstance(item.node, File) and role in ("Role.Manager", "Role.Analyst"):
                    file = item.node
                    hash = ida_nalt.retrieve_input_file_md5()
                    # Remove the trailing null byte, if exists
                    if hash.endswith(b'\x00'):
                        hash = hash[0:-1]
                    hash_current = binascii.hexlify(hash).decode('utf-8')
                    if file is None or file.hash != hash_current:
                        self._parent.set_create_database_button(False)
                    else:
                        self._parent.set_create_database_button(True)
        self._parent._accept_button.setEnabled(False)
        index = self.indexFromItem(item)
        if self.isExpanded(index):
            self.collapse(index)
        else:
            self.expand(index)

    def itemDoubleClickedEvent(self, item, column):
        try:
            if isinstance(item.node, Project) or isinstance(item.node, Folder):
                self._project = item.node
                self._parent._project = item.node
                d = self._plugin.network.send_packet(
                    ListChildren.Query(item.node.id, item.node.__class__.__name__, self._plugin.token))
                d.add_callback(partial(self._children_listed, item))
            elif isinstance(item.node, File):
                file = item.node
                self._file = file
                self._parent._project = item.parent().node
                self._project = item.parent().node
                d = self._plugin.network.send_packet(ListDatabases.Query(item.node.id, self._plugin.token))
                d.add_callback(partial(self._databases_listed))
                self._parent.select_project(file)
        except Exception:
            pass

    def searchItemInTree(self, id: int, type) -> TreeItemWrapper:
        """Search item by ID except Root node"""
        for item in self.findItems("", Qt.MatchContains | Qt.MatchRecursive):

            if (isinstance(item, TreeItemWrapper) and isinstance(item.node, type) and item.node.id == id):
                return item

    def insertSubItem(self, node, item):
        """Insert a subItem under note"""
        item = self.create_node(item)
        item.role = node.role
        try:
            node.addChild(item)
        except Exception:
            pass

    def deleteChild(self, item: TreeItemWrapper) -> None:
        """Delete  item in TreeView"""
        parent = item.parent()
        parent.removeChild(item)

    def create_node(self, item):
        node = TreeItemWrapper(item)
        node.setText(0, item.name)
        if isinstance(item, File):
            self._plugin.logger.debug("file %s  is 64 bit %s " % (item.name, item.is_64bit))
            if item.is_64bit:
                node.setIcon(0, self.icon64bit)
            elif not item.is_64bit and item.is_64bit is not None:
                node.setIcon(0, self.icon32bit)
            else:
                node.setIcon(0, self.prjicon)
        elif isinstance(item, Folder):
            node.setIcon(0, self.diricon)
        elif isinstance(item, Project):
            node.setIcon(0, self.diricon)
        # node.setContextMenuPolicy(Qt.CustomContextMen)
        return node

    def _children_listed(self, item: TreeItemWrapper, reply: ListChildren.Reply):
        # if server send a error we display them with
        if bool(reply.error):
            dialog = ErrorMessage("Error permission", reply.error, self._plugin)
            dialog.exec_()
            return
        files = reply.files
        folders = reply.folders
        # clean subNode of groups
        for i in reversed(range(item.childCount())):
            item.removeChild(item.child(0))
        for file in files:
            self.insertSubItem(item, file)

        for folder in folders:
            self.insertSubItem(item, folder)

    def _databases_listed(self, reply: ListDatabases.Reply):
        if bool(reply.error):
            # display error message
            dialog = ErrorMessage("Permission Denied", reply.error, self._plugin)
            dialog.exec_()
        if hasattr(reply, 'databases'):
            self._parent.databases = reply.databases
        else:
            self._parent.databases = None
        self._parent._database_frame.refresh_database(self._parent.databases)
