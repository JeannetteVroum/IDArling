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
from .models import Project, File, Database, Folder
from .packets import (
    Command,
    Container,
    DefaultCommand,
    ParentCommand,
    Query as IQuery,
    Reply as IReply,
)


class ListProject(ParentCommand):
    __command__ = "list_projects"

    class Query(IQuery, DefaultCommand):
        def __init__(self, token):
            super(ListProject.Query, self).__init__()
            self.token = token

    class Reply(IReply, Command):

        def __init__(self, query, projects, affecteds, error):
            super(ListProject.Reply, self).__init__(query, error)
            self.projects = projects
            self.permissions = affecteds

        def build_command(self, dct):
            dct["projects"] = [{"name": project.name, "id": project.id, "date": project.date.__str__()} for project in
                               self.projects] if self.projects is not None else None
            dct["permissions"] = [{"id_project": affected.projects_id, "role": affected.role} for affected in
                                  self.permissions] if self.permissions is not None else None

        def parse_command(self, dct):
            self.projects = [
                Project(id=project["id"], name=project["name"], date=project["date"]) for project in dct["projects"]
            ]
            self.permissions = dct["permissions"]


class ListChildren(ParentCommand):
    __command__ = "list_children"

    class Query(IQuery, DefaultCommand):
        def __init__(self, id, entity_type, token):
            super(ListChildren.Query, self).__init__()
            self.entity_id = id
            self.entity_type = entity_type
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, folders, files, error):
            super(ListChildren.Reply, self).__init__(query, error)
            self.folders = folders
            self.files = files

        def build_command(self, dct):
            # dct["projects"] = [project.build({}) for project in self.projects]
            dct["files"] = [{"name": file.name, "id": file.id, "hash": file.hash, "file": file.file,
                             "type": file.ftype, "date": file.date, "is_64bit": file.is_64bit} for file in self.files]
            dct['folders'] = [{"name": folder.name, "id": folder.id} for folder in self.folders]

        def parse_command(self, dct):
            self.files = [
                File(id=file["id"], name=file["name"], hash=file["hash"], file=file["file"],
                     ftype=file["type"], date=file["date"], is_64bit=file['is_64bit']) for file in dct["files"]
            ]
            self.folders = [
                Folder(id=folder["id"], name=folder["name"]) for folder in dct["folders"]
            ]


class ListDatabases(ParentCommand):
    __command__ = "list_databases"

    class Query(IQuery, DefaultCommand):
        def __init__(self, file_id: int, token):
            super(ListDatabases.Query, self).__init__()
            self.file_id = file_id
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, databases, error):
            super(ListDatabases.Reply, self).__init__(query, error)
            self.databases = databases

        def build_command(self, dct):
            if self.databases:
                dct["databases"] = [
                    {"name": database.name, "id": database.id, "date": database.date.__str__(), "tick": database.tick,
                     "comment": database.comments}
                    for
                    database in self.databases
                ]

        def parse_command(self, dct):
            if isinstance(dct, dict) and "databases" in dct:
                self.databases = [
                    Database(id=database["id"], date=database["date"], tick=database["tick"], name=database["name"],
                             comments=database["comment"]) for
                    database in dct["databases"]
                ]


class CreateProject(ParentCommand):
    __command__ = "create_project"

    class Query(IQuery, Command):
        def __init__(self, project, token):
            super(CreateProject.Query, self).__init__()
            self.project = project
            self.token = token

        def build_command(self, dct):
            # self.group.build(dct["group"])
            dct["project"] = {"name": self.project.name, "date": self.project.date, "id": self.project.id,
                              "restricted": self.project.restricted}
            dct["token"] = self.token

        def parse_command(self, dct):
            # self.group = Group.new(dct["group"])
            self.project = Project(name=dct["project"]["name"], date=dct["project"]["date"],
                                   restricted=dct["project"]["restricted"])
            self.token = dct["token"]

    class Reply(IReply, Command):

        def __init__(self, query, project, error):
            super(CreateProject.Reply, self).__init__(query, error)
            self.project = project

        def build_command(self, dct):
            dct['project'] = Project.convert_to_dict(self.project)

        def parse_command(self, dct):
            self.project = Project.dict_to_project(dct)


class CreateFile(ParentCommand):
    __command__ = "create_file"

    class Query(IQuery, Command):
        def __init__(self, file, parent_id, parent_type, token):
            super(CreateFile.Query, self).__init__()
            self.file = file
            self.token = token
            self.parent_id = parent_id
            self.parent_type = parent_type

        def build_command(self, dct):
            # self.project.build(dct["project"])
            print("in dict : " + str(self.file))
            dct["file"] = {"name": self.file.name, "project_id": self.file.project_id
                , "hash": self.file.hash, "file": self.file.file, "ftype": self.file.ftype,
                           "date": self.file.date, "folder_id": self.file.folder_id, "is_64bit": self.file.is_64bit}
            dct["token"] = self.token
            dct["parent_id"] = self.parent_id
            dct["parent_type"] = self.parent_type

        def parse_command(self, dct):
            dctProject = dct["file"]
            self.file = File(name=dctProject["name"], date=dctProject["date"], project_id=dctProject["project_id"],
                             hash=dctProject["hash"],
                             file=dctProject["file"], ftype=dctProject["ftype"], folder_id=dctProject["folder_id"],
                             is_64bit=dctProject["is_64bit"])
            self.token = dct["token"]
            self.parent_id = dct["parent_id"]
            self.parent_type = dct["parent_type"]

    class Reply(IReply, Command):

        def __init__(self, query, file, error):
            super(CreateFile.Reply, self).__init__(query, error)
            self.file = file

        def build_command(self, dct):
            if self.file is not None:
                dct["file_id"] = self.file.id

        def parse_command(self, dct):
            if "file_id" in dct:
                self.file = dct['file_id']


class CreateFolder(ParentCommand):
    __command__ = "create_folder"

    class Query(IQuery, Command):
        def __init__(self, folder, parent, token):
            super(CreateFolder.Query, self).__init__()
            self.folder = folder
            self.parent_type = parent.__class__.__name__
            self.parent_id = parent.id
            self.token = token

        def build_command(self, dct):
            dct['folder'] = self.folder.name
            dct['parent_id'] = self.parent_id
            dct['parent_type'] = self.parent_type
            dct["token"] = self.token

        def parse_command(self, dct):
            self.folder = dct["folder"]
            self.parent_id = dct["parent_id"]
            self.parent_type = dct['parent_type']
            self.token = dct['token']

    class Reply(IReply, Command):
        def __init__(self, query, folder_id, error):
            super(CreateFolder.Reply, self).__init__(query, error)
            self.folder_id = folder_id

        def build_command(self, dct):
            if self.folder_id is not None:
                dct["folder_id"] = self.folder_id

        def parse_command(self, dct):
            self.folder_id = dct["folder_id"]


class ListUsersProject(ParentCommand):
    __command__ = "list_users"

    class Query(IQuery, Command):
        def __init__(self, id_project: int, token: str):
            super(ListUsersProject.Query, self).__init__()
            self.id_project = id_project
            self.token = token

        def build_command(self, dct):
            dct["token"] = self.token
            dct["id_project"] = self.id_project

        def parse_command(self, dct):
            self.token = dct["token"]
            self.id_project = dct["id_project"]

    class Reply(IReply, Command):

        def __init__(self, query, permissions: list, error):
            super(ListUsersProject.Reply, self).__init__(query, error)
            self.permissions = permissions

        def build_command(self, dct):
            dct["permissions"] = list()
            for permission in self.permissions:
                dct["permissions"].append(permission)

        def parse_command(self, dct):
            if "permissions" in dct:
                self.permissions = dct["permissions"]


class CreateDatabase(ParentCommand):
    __command__ = "create_database"

    class Query(IQuery, Command):
        def __init__(self, database, is_64bit, fileName, hash, ftype, token):
            super(CreateDatabase.Query, self).__init__()
            self.database = database
            self.token = token
            self.is_64bit = is_64bit
            self.fileName = fileName
            self.hash = hash
            self.ftype = ftype

        def build_command(self, dct):
            dct["token"] = self.token
            dct["database"] = {"name": self.database.name, "file_id": self.database.file_id,
                               "date": self.database.date, "tick": self.database.tick}
            dct["is_64bit"] = self.is_64bit
            dct["filename"] = self.fileName
            dct["hash"] = self.hash
            dct["ftype"] = self.ftype

        def parse_command(self, dct):
            self.token = dct["token"]
            self.is_64bit = dct["is_64bit"]
            self.ftype = dct["ftype"]
            self.fileName = dct["filename"]
            self.hash = dct["hash"]
            dct = dct["database"]
            self.database = Database(name=dct["name"], date=dct["date"], file_id=dct["file_id"])

    class Reply(IReply, Command):

        def __init__(self, query, database, updated, error):
            super(CreateDatabase.Reply, self).__init__(query, error)
            self.database = database
            self.updated = updated

        def build_command(self, dct):
            dct["uptaded"] = self.updated
            if self.database is not None:
                dct["database_id"] = self.database.id

        def parse_command(self, dct):
            self.updated = dct["uptaded"]
            if "database_id" in dct:
                self.database_id = dct["database_id"]


class UpdateFile(ParentCommand):
    __command__ = "update_file"

    class Query(IQuery, Container, DefaultCommand):
        def __init__(self, database_id, token):
            super(UpdateFile.Query, self).__init__()
            self.database_id = database_id
            self.token = token

    class Reply(IReply, Command):
        pass


class SignIn(ParentCommand):
    __command__ = "SignIn"

    class Query(IQuery, DefaultCommand):
        def __init__(self, username, password):
            super(SignIn.Query, self).__init__()
            self.username = username
            self.password = password

    class Reply(IReply, Command):
        def __init__(self, query, error, token):
            super(SignIn.Reply, self).__init__(query, error)
            self.token = token

        def build_command(self, dct):
            dct["token"] = self.token

        def parse_command(self, dct):
            self.token = dct["token"]

class ServerInformation(ParentCommand):
    __command__ ="info_server"

    class Query(IQuery, DefaultCommand):
        def __init__(self):
            super(ServerInformation.Query, self).__init__()

    class Reply(IReply, Command):
        def __init__(self, informations):
            super(ServerInformation.Reply, self).__init__(None, None)
            self.informations = informations

        def build_command(self, dct):
            dct["informations"] = self.informations

        def parse_command(self, dct):
            self.informations = dct["informations"]


class DownloadFile(ParentCommand):
    __command__ = "download_file"

    class Query(IQuery, DefaultCommand):
        def __init__(self, database_id, token):
            super(DownloadFile.Query, self).__init__()
            self.database_id = database_id
            self.token = token

    class Reply(IReply, Container, Command):
        pass


class ChangedRole(ParentCommand):
    __command__ = "changed_role"

    class Query(IQuery, DefaultCommand):

        def __init__(self, project_id, username, role, token):
            super(ChangedRole.Query, self).__init__()
            self.token = token
            self.project_id = project_id
            self.username = username
            self.role = role

    class Reply(IReply, Command):
        def __init__(self, query, error):
            super(ChangedRole.Reply, self).__init__(query, error)


class DeleteItem(ParentCommand):
    __command__ = "delete_item"

    class Query(IQuery, DefaultCommand):

        def __init__(self, type_item, id_item, token):
            super(DeleteItem.Query, self).__init__()
            self.type_item = type_item
            self.id_item = id_item
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, error):
            super(DeleteItem.Reply, self).__init__(query, error)


class RemoveAllUserAffecteds(ParentCommand):
    __command__ = "remove_all_users"

    class Query(IQuery, DefaultCommand):

        def __init__(self, project_id, token):
            super(RemoveAllUserAffecteds.Query, self).__init__()
            self.token = token
            self.project_id = project_id

    class Reply(IReply, Command):
        def __init__(self, query, error):
            super(RemoveAllUserAffecteds.Reply, self).__init__(query, error)


class RenameProject(ParentCommand):
    __command__ = "rename_project"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project_id, new_name, token):
            super(RenameProject.Query, self).__init__()
            self.project_id = project_id
            self.new_name = new_name
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, renamed, error=None):
            super(RenameProject.Reply, self).__init__(query, error)
            self.renamed = renamed

        def build_command(self, dct):
            dct["renamed"] = self.renamed

        def parse_command(self, dct):
            self.renamed = dct["renamed"]


class RenameFile(ParentCommand):
    __command__ = "rename_file"

    class Query(IQuery, DefaultCommand):
        def __init__(self, file_id, new_name, token):
            super(RenameFile.Query, self).__init__()
            self.file_id = file_id
            self.new_name = new_name
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, renamed, error=None):
            super(RenameFile.Reply, self).__init__(query, error)
            self.renamed = renamed

        def build_command(self, dct):
            dct["renamed"] = self.renamed

        def parse_command(self, dct):
            self.renamed = dct["renamed"]


class UpdateComments(ParentCommand):
    __command__ = "update_comments"

    class Query(IQuery, DefaultCommand):
        def __init__(self, database_id, text, token):
            super(UpdateComments.Query, self).__init__()
            self.text = text
            self.token = token
            self.database_id = database_id

    class Reply(IReply, Command):
        def __init__(self, query, error=None):
            super(UpdateComments.Reply, self).__init__(query, error)


class RenameFolder(ParentCommand):
    __command__ = "rename_folder"

    class Query(IQuery, DefaultCommand):
        def __init__(self, folder_id, new_name, token):
            super(RenameFolder.Query, self).__init__()
            self.folder_id = folder_id
            self.new_name = new_name
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, renamed, error=None):
            super(RenameFolder.Reply, self).__init__(query, error)
            self.renamed = renamed

        def build_command(self, dct):
            dct["renamed"] = self.renamed

        def parse_command(self, dct):
            self.renamed = dct["renamed"]


class RenameSnapshot(ParentCommand):
    __command__ = "rename_snapshot"

    class Query(IQuery, DefaultCommand):
        def __init__(self, database_id, new_name, token):
            super(RenameSnapshot.Query, self).__init__()
            self.database_id = database_id
            self.new_name = new_name
            self.token = token

    class Reply(IReply, Command):
        def __init__(self, query, renamed, error=None):
            super(RenameSnapshot.Reply, self).__init__(query, error)
            self.renamed = renamed

        def build_command(self, dct):
            dct["renamed"] = self.renamed

        def parse_command(self, dct):
            self.renamed = dct["renamed"]


class JoinSession(DefaultCommand):
    __command__ = "join_session"

    def __init__(self, database_id, tick, name, color, ea, token, silent=True):
        super(JoinSession, self).__init__()
        self.database_id = database_id
        self.tick = tick
        self.name = name
        self.color = color
        self.ea = ea
        self.silent = silent
        self.token = token


class LeaveSession(DefaultCommand):
    __command__ = "leave_session"

    def __init__(self, name, token, silent=True):
        super(LeaveSession, self).__init__()
        self.name = name
        self.silent = silent
        self.token = token


class UpdateUserName(DefaultCommand):
    __command__ = "update_user_name"

    def __init__(self, old_name, new_name):
        super(UpdateUserName, self).__init__()
        self.old_name = old_name
        self.new_name = new_name


class UpdateUserColor(DefaultCommand):
    __command__ = "update_user_color"

    def __init__(self, name, old_color, new_color):
        super(UpdateUserColor, self).__init__()
        self.name = name
        self.old_color = old_color
        self.new_color = new_color


class UpdateLocation(DefaultCommand):
    __command__ = "update_location"

    def __init__(self, name, ea, color):
        super(UpdateLocation, self).__init__()
        self.name = name
        self.ea = ea
        self.color = color


class InviteToLocation(DefaultCommand):
    __command__ = "invite_to_location"

    def __init__(self, name, loc):
        super(InviteToLocation, self).__init__()
        self.name = name
        self.loc = loc


class UpdateNotepad(DefaultCommand):
    __command__ = "update_notepad"

    def __init__(self, text):
        super(UpdateNotepad, self).__init__()
        self.text = text
