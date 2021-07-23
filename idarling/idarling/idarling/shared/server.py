# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import bz2
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import json
import logging
import secrets
import socket
import ssl
import threading

import os

from .Authentification import Authentification
from .channel import Channel
from .commands import (
    CreateProject,
    CreateFile,
    CreateDatabase,
    DownloadFile,
    InviteToLocation,
    JoinSession,
    LeaveSession,
    ListProject,
    ListDatabases,
    RenameProject,
    RenameFile,
    UpdateFile,
    UpdateLocation,
    UpdateUserColor,
    UpdateUserName,
    SignIn,
    UpdateNotepad,
    ListChildren,
    CreateFolder,
    RenameFolder,
    ListUsersProject,
    ChangedRole,
    RemoveAllUserAffecteds,
    DeleteItem,
    UpdateComments, RenameSnapshot)
from .discovery import ClientsDiscovery
from .error import Error
from .models import User, Affected
from .packets import Command, Event
from .sockets import ClientSocket, ServerSocket
from .storage import Storage
from idarling.shared import error, utils


class ServerClient(ClientSocket):
    """
    This class represents a client socket for the server. It implements all the
    handlers for the packet the client is susceptible to send.
    """

    def __init__(self, logger, parent=None):
        """

        @type parent: Server
        """

        ClientSocket.__init__(self, logger, parent)
        self._parent = parent
        self._authentification = Authentification(logger, parent)
        self._database_id = None
        self._name = None
        self._color = None
        self._ea = None
        # initialize the channel
        self._can_write_event = None
        self._handlers = {}
        # we need to delete all snapshot not include in db
        self.delete_all_snapshot()

    @property
    def can_write_event(self):
        return self._can_write_event

    @property
    def database_id(self):
        return self._database_id

    @property
    def name(self):
        return self._name

    @property
    def color(self):
        return self._color

    @property
    def ea(self):
        return self._ea

    def super_send_packet(self, packet):
        self.send_packet(packet)

    def wrap_socket(self, sock):
        ClientSocket.wrap_socket(self, sock)

        # Setup command handlers
        self._handlers = {
            ListProject.Query: self._handle_list_projects,
            ListChildren.Query: self._handle_list_children,
            ListDatabases.Query: self._handle_list_databases,
            CreateProject.Query: self._handle_create_project,
            CreateFile.Query: self._handle_create_file,
            CreateFolder.Query: self._handle_create_folder,
            CreateDatabase.Query: self._handle_create_database,
            UpdateFile.Query: self._handle_upload_file,
            DownloadFile.Query: self._handle_download_file,
            RenameFile.Query: self._handle_rename_file,
            RenameProject.Query: self._handle_rename_project,
            RenameFolder.Query: self._handle_rename_folder,
            RenameSnapshot.Query: self._handle_rename_snapshot,
            SignIn.Query: self._handle_signin,
            JoinSession: self._handle_join_session,
            LeaveSession: self._handle_leave_session,
            UpdateLocation: self._handle_update_location,
            InviteToLocation: self._handle_invite_to_location,
            UpdateUserName: self._handle_update_user_name,
            UpdateUserColor: self._handle_update_user_color,
            UpdateNotepad: self._handle_update_notepad,
            ListUsersProject.Query: self._handle_list_permission_for_project,
            ChangedRole.Query: self._handle_change_role_for_project,
            RemoveAllUserAffecteds.Query: self._handle_remove_all_user_from_project,
            DeleteItem.Query: self._handle_remove_item,
            UpdateComments.Query: self._handle_update_comments

        }

        # Add host and port as a prefix to our logger
        prefix = "%s:%d" % sock.getpeername()

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return "(%s) %s" % (prefix, msg), kwargs

        self._logger = CustomAdapter(self._logger, {})
        self._logger.info("Connected")

    def disconnect(self, err=None, notify=True):
        # Notify other users that we disconnected
        if len(self._parent._auths) > 0:
            token = list(self._parent._auths)[0]
            user = self._search_user(token)
            self._remove_user(token)
            self.parent().storage.remove_lock(user, self._database_id)
        self.parent().reject(self)
        if self._database_id and notify:
            self.parent().forward_users(self, LeaveSession(self.name, False))
        ClientSocket.disconnect(self, err)
        self._logger.info("Disconnected")

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            if not self._database_id:
                self._logger.warning(
                    "Received a packet from an unsubscribed client"
                )
                return True

            # Check for de-synchronization
            tick = self.parent().storage.last_tick(
                self._database_id
            )
            if tick >= packet.tick:
                self._logger.warning("De-synchronization detected!")
                packet.tick = tick + 1
            # only user have the permission to update database
            if self._can_write_event:
                # Save the event into the database
                if packet.token in self._parent._auths:
                    user = self._parent._auths[packet.token]
                    # @todo her
                    self.parent().storage.insert_event(self, packet, user)
                    # Forward the event to the other users
                    self.parent().forward_users(self, packet)
                else:
                    return False

            # Ask for a snapshot of the database if needed
            interval = self.parent().SNAPSHOT_INTERVAL
            if packet.tick and interval and packet.tick % interval == 0:
                def file_downloaded(reply):
                    file_name = "%s_%s_%s.idb" % (self._group, self._project, self._database)
                    file_path = self.parent().server_file(file_name)

                    # Write the file to disk
                    with open(file_path, "wb") as output_file:
                        output_file.write(reply.content)
                    self._logger.info("Auto-saved file %s" % file_name)

                d = self.send_packet(
                    DownloadFile.Query(self._group, self._project, self._database)
                )
                d.add_callback(file_downloaded)
                d.add_errback(self._logger.exception)
        else:
            return False
        return True

    def _handle_signin(self, query: SignIn.Query):
        self._logger.info("User %s try to connect to IDArling" % (query.username))
        response = self._authentification.authenticate(username=query.username, password=query.password,
                                                       )

        if isinstance(response, Error):
            self._logger.warning("Error %s for user %s" % (response, query.username))
            self.send_packet(SignIn.Reply(query, response, None))
            return
        if "@" in query.username:
            username, search_base = utils.searchDc(query.username)
        else:
            username = query.username
        user = self.parent().storage.select_user_by_username(username)
        self.parent().storage.modify_last_connection(user)
        if user is not None:
            token = secrets.token_hex(64)
            self._parent._auths[token] = user
            self.send_packet(SignIn.Reply(query, None, token))

    def _handle_rename_project(self, query):
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        project = self.parent().storage.select_project(query.project_id)
        old_name = project.name
        ret = self.parent().storage.rename_project(project, query.new_name, user)
        if isinstance(ret, Error):
            self._logger.warning("_handle_rename_project  user : %s try to rename project with id : %d, msg : %s " % (
                user.username, project.id, ret.name))
            self.send_packet(RenameProject.Reply(query, False, ret))
            return
        self._logger.info(
            "User %s rename project id:%d  name:%s  to  %s " % (user.username, project.id, old_name, query.new_name))
        self.send_packet(RenameProject.Reply(query, True))

    def _handle_rename_file(self, query):
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        file = self.parent().storage.select_file(query.file_id)
        project = self.parent().storage.select_project_of_entity(file)
        ret = self.parent().storage.rename_file(project, file, query.new_name, user)
        if isinstance(ret, Error):
            self._logger.warning("_handle_rename_file  user : %s try to rename file with id : %d, msg : %s " % (
                user.username, file.id, ret.name))
            self.send_packet(RenameFile.Reply(query, False, ret))
            return
        self.send_packet(RenameFile.Reply(query, True))

    def _handle_rename_folder(self, query):
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        folder = self.parent().storage.select_folder(query.folder_id)
        project = self.parent().storage.select_project_of_entity(folder)
        ret = self.parent().storage.rename_folder(project, folder, query.new_name, user)
        if isinstance(ret, Error):
            self._logger.warning("_handle_rename_file  user : %s try to rename file with id : %d, msg : %s " % (
                user.username, folder.id, ret.name))
            self.send_packet(RenameFolder.Reply(query, False, ret))
            return
        self.send_packet(RenameFolder.Reply(query, True))

    def _handle_rename_snapshot(self, query: RenameSnapshot.Query):
        user = self._search_user(query.token)
        error, snapshot = self.parent().storage.select_database(query.database_id, user)
        project = self.parent().storage.select_project_of_entity(snapshot)
        ret = self.parent().storage.rename_snapshot(snapshot, query.new_name, project, user)
        if isinstance(ret, Error):
            self._logger.warning("_handle_rename_snapshot  user : %s try to rename snapshot with id : %d, msg : %s " %
                                 (user.username, snapshot.id, ret.name))
            self.send_packet(RenameSnapshot.Reply(query, False, ret))
            return
        self.send_packet(RenameSnapshot.Reply(query, True))

    def _handle_list_projects(self, query):
        """
        handle list project
        Returns an error if the user is not authenticated.
        Else return list of pojects when the user have a rôle
        :param query:
        :return:
        """
        self.parent().storage.refresh_session()
        try:
            user = self._search_user(query.token)
            self._logger.info("User %s list projects" % user.username)
        except Exception:
            error = Error.AUTHENTIFICATION_REQUIRED
            self.send_packet(ListProject.Reply(query, None, None, error))
            self.parent().storage.refresh_session()
            return
        projects = self.parent().storage.select_projects(user)
        affecteds = self.parent().storage.select_permissions(user)
        self.send_packet(ListProject.Reply(query, projects, affecteds, None))

    def _handle_list_permission_for_project(self, query: ListUsersProject.Query):
        """
        Return all users's permissions for a project
        Check if user can say who is affected
        """
        error = None
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        error, mapping = self.parent().storage.select_all_affected_user_for_project(user, query.id_project)
        self.send_packet(ListUsersProject.Reply(query, mapping, error))

    def _search_user(self, token: str) -> User:
        """Search for the user corresponding to the token """
        user = self._parent._auths[token]
        return user

    def _remove_user(self, token: str) -> None:
        if token in self._parent._auths:
            del self._parent._auths[token]

    def _handle_list_children(self, query):
        user = self._search_user(query.token)
        self.parent().storage.refresh_session()

        entity_type = query.entity_type
        entity_id = query.entity_id
        entity = self.parent().storage.select_entity_by_id_and_type(entity_id, entity_type)
        # select children and send them
        error, folders, files = self.parent().storage.select_children(entity)
        self.send_packet(ListChildren.Reply(query, folders, files, error))

    def _handle_list_databases(self, query: ListDatabases.Query):
        user = self._search_user(query.token)
        self.parent().storage.refresh_session()
        error, databases = self.parent().storage.select_databases(query.file_id, user)
        if bool(error):
            self._logger.info("Error permissions, user %s try to opening project %d" % (user, query.file_id))
            self.send_packet(ListDatabases.Reply(query, databases, error))
            return
        for database in databases:
            file_name = "%d.idb" % (database.id)
            file_path = self.parent().server_file(file_name)
            if os.path.isfile(file_path):
                database.tick = self.parent().storage.last_tick(database.id)
            else:
                database.tick = -1
        self.send_packet(ListDatabases.Reply(query, databases, error))

    def _handle_update_notepad(self, packet):
        """Update database content with the new value of notepad and forward the content to other's user"""
        # only user have the permission to update database
        if self._can_write_event:
            notepad_content = packet.text
            self.parent().storage.update_notepad(self._database_id, notepad_content)
            # send sql notify to postgreSQL server
            # self.channel.send_modification_notepad(self._database_id)
            # Forward the event to the other users
            self.parent().forward_users(self, packet)

    def _handle_create_project(self, query):
        error = None
        user = self._search_user(query.token)
        self.parent().storage.refresh_session()

        project = self.parent().storage.insert_project(query.project, user)
        self.send_packet(CreateProject.Reply(query, project, error))

    def _handle_create_file(self, query):
        """
        Handle query for create file
        :param query:
        """
        user = self._search_user(query.token)
        self.parent().storage.refresh_session()
        self._logger.info("User %s try to create file %s, parent is %s, %d is 64_bit %s" % (
            user.username, query.file, query.parent_type, query.parent_id, query.file.is_64bit))
        error, file = self.parent().storage.insert_file(query.file, user, query.parent_id, query.parent_type)
        self.send_packet(CreateFile.Reply(query, file, error))

    def _handle_create_folder(self, query):
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        self._logger.info("User %s try to create folder %s, parent is %s,%s" % (
            user.username, query.folder, query.parent_type, query.parent_id))
        error, folder = self.parent().storage.insert_folder(query.folder, user, query.parent_type, query.parent_id)
        self.send_packet(CreateFolder.Reply(query, folder.id, error))

    def _handle_create_database(self, query: CreateDatabase.Query):
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        updated = False  # True if file's information is updated
        if query.is_64bit is not None:
            """We check that the file that will contain the binary is already initialized if not we update the information."""
            self._logger.debug("In query database %s " % query.database.file_id)
            file = self.parent().storage.select_file(query.database.file_id)
            self._logger.debug("File is 64 is " + str(file.is_64bit))
            if file.is_64bit is None:
                self._logger.debug("File is 64 is None")
                project = self.parent().storage.select_project_of_entity(file)
                self._logger.debug("project is %s " % project)
                if not User.can_update_database(self.parent().storage.s, user, project):
                    error = Error.PERMISSION_NOT_ALLOWED
                    self.send_packet(CreateDatabase.Reply(query, None, False, error))
                    return
                else:
                    self._logger.debug("Update them")
                    # we update the file's information (name,hash and architecture)
                    updated = True
                    self.parent().storage.update_file_information(file.id, name=query.fileName, hash=query.hash,
                                                                  is_64bit=query.is_64bit, ftype=query.ftype)
                    self._logger.debug("After is_64 %s and is name %s " % (file.is_64bit, file.name))
        error, database = self.parent().storage.insert_database(query.database, user)
        self.send_packet(CreateDatabase.Reply(query, database, updated, error))

    def _handle_upload_file(self, query):
        user = self._search_user(query.token)
        self.parent().storage.refresh_session()

        error, database = self.parent().storage.select_database(
            query.database_id, user
        )
        project = self.parent().storage.select_project_of_entity(database)
        if (not User.can_update_database(self.parent().storage.s, user, project)):
            self.send_packet(UpdateFile.Reply(query, Error.PERMISSION_NOT_ALLOWED))
            return

        file_name = "%d.idb" % (database.id)
        file_path = self.parent().server_file(file_name)

        # Write the file received to disk
        decompressed_content = bz2.decompress(query.content)
        with open(file_path, "wb") as output_file:
            output_file.write(decompressed_content)
        self._logger.info("Saved file %s" % file_name)
        self.send_packet(UpdateFile.Reply(query, error))

    def _handle_download_file(self, query):
        user = self._search_user(query.token)
        _, database = self.parent().storage.select_database(query.database_id, user)
        if not database:
            self._logger.info(
                "User %s don't have the permission to read database %d" % (user.username, self._database_id))
        project = self.parent().storage.select_project_of_entity(database)
        if not User.can_read_database(self.parent().storage.s, user, project, query.database_id):
            reply = DownloadFile.Reply(query, Error.PERMISSION_NOT_ALLOWED)
            reply.content = bz2.compress(b"error")
            self.send_packet(reply)
            return
        error, database = self.parent().storage.select_database(
            query.database_id, user
        )
        if bool(error):
            reply = DownloadFile.Reply(query, error)
            db_id = database.id
            reply.content = bz2.compress(b"error")
            username = user.username
            self._logger.info("User %s try to read database: %s without permission" % (username, db_id))
            self.send_packet(reply)
            return
        file_name = "%d.idb" % (database.id)
        file_path = self.parent().server_file(file_name)

        # Read file from disk and sent it
        reply = DownloadFile.Reply(query, error)
        reply.path = file_name
        with open(file_path, "rb") as input_file:
            uncompressed_content = input_file.read()
        reply.content = bz2.compress(uncompressed_content)
        self._logger.info("Loaded file %s" % file_name)
        self.send_packet(reply)

    def _handle_change_role_for_project(self, query: ChangedRole.Query):
        """
        Change the user's permission on the project
        Verifies that the user at the origin of the action is a manager or an administrator.
        Does not allow to switch from the administrator role to another or to assign the administrator role        @param query:
        @type query:
        @return: reply
        @rtype:
        """
        error = None
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        user_to_change = self.parent().storage.select_user_by_username(query.username)

        self._logger.info("User %s wants to change the role of the %s user for the project %d"
                          "to %s" % (user.username, user_to_change.username, query.project_id,
                                     query.role))
        project = self.parent().storage.select_project(query.project_id)
        if not user.can_modify_project(self.parent().storage.s, user, project):
            # return error
            self._logger.exception("Permission to change role Denied")
            error = Error.PERMISSION_NOT_ALLOWED
        else:
            role = user_to_change.getRole(self.parent().storage.s, project, user_to_change)
            if role == role.Admin:
                self._logger.exception("Can't affect Admin role")
                error = Error.PERMISSION_NOT_ALLOWED
            else:
                new_role = Affected.Role[query.role]
                self._logger.info("Role changed new role is %s " % new_role)
                self.parent().storage.setRole(project, user_to_change, new_role)


    def _handle_remove_all_user_from_project(self, query: RemoveAllUserAffecteds.Query):
        self._logger.debug("Handle _handle_remove_all_user_from_project")
        self.parent().storage.refresh_session()
        user = self._search_user(query.token)
        error = None
        project = self.parent().storage.select_project(query.project_id)
        if not user.can_modify_project(self.parent().storage.s, user, project):
            # return error
            error = Error.PERMISSION_NOT_ALLOWED
            self.send_packet(RemoveAllUserAffecteds.Reply(query, error))
            return
        self.parent().storage.remove_all_users_affected_to_project(project, user)
        self.send_packet(RemoveAllUserAffecteds.Reply(query, error))

    def _handle_remove_item(self, query: DeleteItem.Query):
        """
        Remove a project/folder/file or snapshot
        @param query:
        @type query: DeleteItem.Quer
        @return:
        @rtype:
        """
        error = None
        user = self._search_user(query.token)
        object = self.parent().storage.select_entity_by_id_and_type(query.id_item, query.type_item)
        project = self.parent().storage.select_project_of_entity(object)
        # check if user is affected to reader or analyst
        permissions = self.parent().storage.select_all_permission_reader_analyst_for_project(project)
        if bool(permissions):  # Exist reader or analyst on this project
            self._logger.debug("A user is assigned to the project and consequently deletion is not possible ")
            self.send_packet(DeleteItem.Reply(query, Error.READER_OR_ANALYST_AFFECTED))
            return
        # check if user have the permission to delete the object
        can_delete_item = User.can_modify_project(self.parent().storage.s, user, project)
        if can_delete_item:
            log = "User %s delete %s " % (user.username, object)
            self._logger.info(log)
            self.parent().storage.delete_object_and_children(object)
            self.send_packet(DeleteItem.Reply(query, None))
        else:
            self._logger.warning(
                "User %s try to delete %s with id %d  without permission" % (user.username, object.__class__.__name__,
                                                                             object.id))

    def _handle_join_session(self, packet):
        # @todo verify if user can acces to db
        if packet.token is not None:
            user = self._search_user(packet.token)
            if self._database_id is not None:
                self._logger.info(
                    "User %s leave database %d and join session for database %d" % (user.username, self._database_id,
                                                                                    packet.database_id))
            self._database_id = packet.database_id
            self._logger.info("User %s join session for database %d" % (user.username, self._database_id))
            self.parent().storage.refresh_session()
            _, database = self.parent().storage.select_database(self._database_id, user)
            if not database:
                self._logger.info(
                    "User %s don't have the permission to read database %d" % (user.username, self._database_id))
            else:  # lock database
                self.parent().storage.insert_lock(user, database)
            project = self.parent().storage.select_project_of_entity(database)
            can_update_database = User.can_update_database(self.parent().storage.s, user, project)
            self._logger.info(
                "User %s has the permission to update database :  %s" % (user.username, can_update_database))
            self._can_write_event = can_update_database
            self._name = packet.name
            self._color = packet.color
            self._ea = packet.ea

            # Inform the other users that we joined
            packet.silent = False
            self.parent().forward_users(self, packet)

            # Inform ourselves about the other users
            for user in self.parent().get_users(self):
                self.send_packet(
                    JoinSession(
                        packet.database_id,
                        packet.tick,
                        user.name,
                        user.color,
                        user.ea,
                        None  # we don't send other user token

                    )
                )

            # Send all missed events
            events = self.parent().storage.select_events(
                self._database_id, packet.tick
            )
            self._logger.debug("Sending %d missed events..." % len(events))
            for event in events:
                self.send_packet(event)
            self._logger.debug("Done sending %d missed events" % len(events))
            # Send content of notepad
            notepad_content = self.parent().storage.select_notepad(self._database_id)
            self.send_packet(UpdateNotepad(notepad_content))
            self._logger.debug("Send content of notepad")

    def _handle_leave_session(self, packet):
        # Inform others users that we are leaving
        user = self._search_user(packet.token)
        packet.silent = False
        self.parent().storage.remove_lock(user, self._database_id)
        self.parent().forward_users(self, packet)

        # Inform ourselves that the other users leaved
        for user in self.parent().get_users(self):
            self.send_packet(LeaveSession(user.name, packet.token))
        self._database_id = None
        self._can_write_event = None
        self._name = None
        self._color = None

    def _handle_update_location(self, packet):
        self.parent().forward_users(self, packet)

    def _handle_invite_to_location(self, packet):
        def matches(other):
            return other.name == packet.name or packet.name == "everyone"

        packet.name = self._name
        self.parent().forward_users(self, packet, matches)

    def _handle_update_user_name(self, packet):
        # FXIME: ensure the name isn't already taken
        self._name = packet.new_name
        self.parent().forward_users(self, packet)

    def _handle_update_user_color(self, packet):
        self.parent().forward_users(self, packet)

    def delete_all_snapshot(self):
        """Delete all old databases contains in  folder <project_path>/files"""
        self._logger.info("Delete all old snapshot")
        databases = [str(database.id) + ".idb" for database in self.parent().storage.get_all_databases()]
        plugin_path = os.path.abspath(os.path.dirname(__file__))
        folder_path = os.path.join(plugin_path, "..", "files")
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, 493)  # 0755
        files = os.listdir(folder_path)
        for file in files:
            if file.endswith(".idb") and file not in databases:
                self._logger.info("Delete snapshot %s" % file)
                os.remove(os.path.join(folder_path, file))

    def _handle_update_comments(self, query: UpdateComments.Query):
        error = None
        user = self._search_user(query.token)
        _, database = self.parent().storage.select_database(query.database_id, user)
        project = self.parent().storage.select_project_of_entity(database)
        if User.can_update_database(self.parent().storage.s, user, project):
            self.parent().storage.update_comments(query.database_id, query.text)
        else:
            error = Error.PERMISSION_NOT_ALLOWED
        self.send_packet(UpdateComments.Reply(query, error))


class Server(ServerSocket):
    """
    This class represents a server socket for the server. It is used by both
    the integrated and dedicated server implementations. It doesn't do much.
    """

    SNAPSHOT_INTERVAL = 0  # ticks

    def __init__(self, logger, parent=None, level=None):
        ServerSocket.__init__(self, logger, parent)
        self._ssl = None
        self._clients = []
        self._auths = dict()

        # Load the configuration
        self._config_path = self.server_file("config_server.json")
        self._config = self.default_config()
        self.load_config()
        if level != None:
            self._logger.setLevel(level)
        else:
            self._logger.setLevel(self._config["level"])
        self.save_config()
        self._channel = Channel(self, logger)
        # Initialize the storage
        self._storage = Storage(logger, self._channel)
        # get setttings from databases
        self._discovery = ClientsDiscovery(logger)
        # A temporory lock to stop clients while updating other locks
        self.client_lock = threading.Lock()
        # A long term lock that stops breaking database updates when multiple
        # clients are connected
        self.db_update_lock = threading.Lock()

    @property
    def config_path(self):
        return self._config_path

    @property
    def config(self):
        return self._config

    @property
    def storage(self):
        return self._storage

    @property
    def host(self):
        return self._socket.getsockname()[0]

    @property
    def port(self):
        return self._socket.getsockname()[1]

    @staticmethod
    def default_config():
        """
        Return the default configuration options. This is used to initialize
        the configuration file the first time the server is started
        """
        return {
            "level": logging.INFO,
            # "migration": 0,
        }

    def load_config(self):
        """
        Load the configuration file. It is a JSON file that contains all the
        settings of the server.
        """
        if not os.path.isfile(self.config_path):
            return
        with open(self.config_path, "rb") as config_file:
            try:
                self._config.update(json.loads(config_file.read()))
            except ValueError:
                self._logger.warning("Couldn't load config file")
                return
            self._logger.debug("Loaded config: %s" % self._config)

    def save_config(self):
        """Save the configuration file."""
        self._config["level"] = self._logger.level
        with open(self.config_path, "w") as config_file:
            config_file.write(json.dumps(self._config))
            self._logger.debug("Saved config: %s" % self._config)

    def send_web_application_changes(self, database_id: str):
        # retrieve content of notepad
        database_id = database_id.split('_')[0]
        content = self._storage.select_notepad(database_id)
        for client in self._clients:
            if client.database_id == int(database_id):
                # packet = UpdateLocation(name="analyst3",ea=6442455661, color=11337983)
                # client.super_send_packet(packet)
                packet = UpdateNotepad(content)
                client.send_packet(packet)
                client._notify_write()

    def start(self, host, port=0, ssl_=None):
        """Starts the server on the specified host and port."""
        self._logger.info("Starting the server on %s:%d" % (host, port))

        # Load the system certificate chain
        self._ssl = ssl_
        if self._ssl:
            cert, key = self._ssl
            self._ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._ssl.load_cert_chain(certfile=cert, keyfile=key)

        # Create, bind and set the socket options
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except socket.error as e:
            self._logger.warning("Could not start the server")
            self._logger.exception(e)
            return False
        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        sock.listen(5)
        self.connect(sock)

        # Start discovering clients
        host, port = sock.getsockname()
        self._discovery.start(host, port, self._ssl)
        return True

    def stop(self):
        """Terminates all the connections and stops the server."""
        self._logger.info("Stopping the server")
        self._discovery.stop()
        # Disconnect all clients
        for client in list(self._clients):
            client.disconnect(notify=False)
        self.disconnect()
        self._channel.terminate_listen()
        try:
            self.db_update_lock.release()
        except RuntimeError:
            # It might not actually be locked
            pass
        return True

    def _accept(self, sock):
        """Called when an user connects."""
        client = ServerClient(self._logger, self)

        if self._ssl:
            # Wrap the socket in an SSL tunnel
            sock = self._ssl.wrap_socket(
                sock, server_side=True, do_handshake_on_connect=False
            )

        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking

        # If we already have at least one connection, lock the mutex that
        # prevents database updates like renaming. Connecting clients will
        # block until an existing blocking operation, like a porject rename, is
        # completed
        self.client_lock.acquire()
        if len(self._clients) == 1:
            self.db_update_lock.acquire()
        client.wrap_socket(sock)
        self._clients.append(client)
        self.client_lock.release()

    def reject(self, client):
        """Called when a user disconnects."""

        # Allow clients to update database again
        self.client_lock.acquire()
        self._clients.remove(client)
        if len(self._clients) <= 1:
            try:
                self.db_update_lock.release()
            except RuntimeError:
                pass

        self.client_lock.release()

    def get_users(self, client, matches=None):
        """Get the other users on the same database."""
        users = []
        for user in self._clients:
            if (

                    user.database_id != client.database_id
            ):
                continue
            if user == client or (matches and not matches(user)):
                continue
            users.append(user)
        return users

    def forward_users(self, client, packet, matches=None):
        """Sends the packet to the other users on the same database."""
        for user in self.get_users(client, matches):
            user.send_packet(packet)

    def server_file(self, filename):
        """Get the absolute path of a local resource."""
        raise NotImplementedError("server_file() not implemented")
