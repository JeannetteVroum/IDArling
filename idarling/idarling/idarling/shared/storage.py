# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import configparser
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import datetime
import json
from typing import Tuple, Optional, Union, List

import os
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker

from .error import Error
from .models import Project, File, User, Database, Event, Affected, Setting, Folder, Lock
from .packets import DefaultEvent


class Storage(object):
    """
    This object is used to access the SQL database used by the server. It
    also defines some utility methods. Currently, only SQLite3 is implemented.
    """

    def __init__(self, logger, channel):
        config = configparser.ConfigParser()
        cwd, _ = os.path.split(os.path.abspath(__file__))
        path = os.path.join(cwd, "..", "..", "setting_server.ini")
        config.read(path)
        host =os.environ.get("SQL_HOST", config["Database"]["IP"])
        user = os.environ.get("SQL_USER",  config["Database"]["user"])
        password = os.environ.get("SQL_PASSWORD", config["Database"]["password"])
        database_name = os.environ.get("SQL_DATABASE",  config["Database"]["name"] )
        engine_url = f"postgresql://{user}:{password}@{host}/{database_name}"
        self.logger = logger
        self.logger.debug(f"engine_url {engine_url}")
        self.engine = create_engine(engine_url)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.s = self.Session()
        self.channel = channel

    def refresh_session(self):
        self.s.close()
        self.s = self.Session()

    def get_authentification_by_ldap_is_allowed(self):
        """
        Check if authentification LDAP is allowed
        :return True if allowed else False:
        """
        try:
            value = self.s.query(Setting).first().authentification_ldap
            if os.environ.get("AUTHENTIFICATION_BY_LDAP") != "True":
                authentification_by_ldap = False
            if os.environ.get("AUTHENTIFICATION_BY_USERNAME_PASSWORD") != "True":
                authentification_by_username_password = False
        except Exception as e:
            value = Setting(authentification_by_username_password=authentification_by_username_password,authentification_by_ldap=authentification_by_ldap)
            value.save()
        return value

    def get_authentification_by_username_password_is_allowed(self):
        """
        Check if normal authentification  is allowed
        :return True if allowed else False:
        """
        value = self.s.query(Setting).first().authentification_username_password
        return value

    def select_projects(self, user):
        """Select the all Project when user have the permission."""
        projects = [project for project in self.s.query(Project).all() if User.can_read_project(self.s, user, project)]
        self.s.close()
        return projects

    def select_all_affected_user_for_project(self, user: User, project_id: int):
        project = self.s.query(Project).get(project_id)
        databases = self.retrieve_all_databases(project)
        users_locked = self.select_user_work_on_databases(databases)
        if user.can_modify_project(self.s, user, project):
            mapping = list()
            for user in self.s.query(User).all():
                affected = self.s.query(Affected).filter(Affected.user == user).filter(
                    Affected.projects == project).first()
                # check if user work on db
                if user in users_locked:
                    mapping.append((user.username, affected.role, True))
                else:
                    mapping.append((user.username, affected.role, False))
            return None, mapping
        else:
            return Error.PERMISSION_NOT_ALLOWED, None

    def select_affected_for_project(self, project: Project):
        return self.s.query(Affected).filter(
            Affected.projects == project).all()

    def update_group_name(self, project: Project, name: str):
        """Update group name
        @param project: project when the name need to be update
        @type project: Project
        @param name: new name of the project
        @type name: str
        """
        project.name = name
        self.s.commit()
        self.s.close()

    def insert_file(self, file, user, parent_id, parent_type):
        """Insert a new project in the db.
        :param file: file to be create
        :type file: File
        :param user: User
        :type user: User
        :return: Error and none if user don't have the permission to create file else None, File
        :rtype: tuple, File created
        """
        parent = self.select_entity_by_id_and_type(parent_id, parent_type)
        project = self.select_project_of_entity(parent)
        can_create = User.can_create_file(self.s, user, project)
        if can_create:
            if isinstance(parent, Folder):
                file.folder = parent
            elif isinstance(parent, Project):
                file.project = parent
            self.s.add(file)
            self.s.commit()
            self.s.close()
            return None, file
        else:
            error = Error.PERMISSION_NOT_ALLOWED
            return error, None

    def select_project(self, id: int) -> object:
        """Select the project with the given id."""
        objects = self.s.query(Project).filter(Project.id == id).all()
        self.s.close()
        return objects[0] if objects else None

    def delete_object_and_children(self, object):
        """
        Retrieve children delete and them
        :param object:
        :return:
        """
        try:
            self.logger.debug("In delete_object")
            if isinstance(object, Project):
                # remove all affectations
                affectations = self.select_affected_for_project(object)
                for affectation in affectations:
                    self.s.delete(affectation)
            databases = self.retrieve_all_databases(object)
            for database in databases:
                # delete events
                self.s.query(Event).filter(Event.database == database).delete()
                # check if lock exist and delete them
                self.s.query(Lock).filter(Lock.database == database).delete()
                self.s.delete(database)
            # delete subFolder
            self.logger.debug("Object is " + str(object))
            if not (isinstance(object, File) or isinstance(object, Database)):
                _, childrensfolder, childrensFile = self.select_children(object)
                for children in childrensfolder:
                    self.s.delete(children)
                for children in childrensFile:
                    self.s.delete(children)
            self.s.delete(object)
            self.s.commit()
        except Exception as e:
            self.logger.debug("Bug is " + str(e))

    def insert_project(self, project: Project, user_current: User) -> Project:
        """Create project"""
        self.s.add(project)
        # For user exist except current and admin  we attribute reader role
        if not project.restricted:
            users = self.s.query(User).filter(User.username != user_current.username).filter(
                User.is_superuser != True).all()
            for user in users:
                affected = Affected(user=user, projects=project, role=Affected.Role.Reader)
                self.s.add(affected)
        users = self.s.query(User).filter(User.username != user_current.username).filter(
            User.is_superuser == True).all()
        for user in users:
            affected = Affected(user=user, projects=project, role=Affected.Role.Admin)
            self.s.add(affected)
        affected = Affected(user=user_current, projects=project, role=Affected.Role.Manager)
        self.s.add(affected)
        self.s.commit()
        self.s.close()
        return project

    def rename_project(self, project: Project, new_name: str, user: User):
        """Check user permission for modify name"""
        self.refresh_session()
        affected = self.s.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected.role == affected.role.Manager:
            project = self.s.query(Project).get(project.id)
            project.name = new_name
            self.s.commit()
            return True
        else:
            return Error.PERMISSION_NOT_ALLOWED

    def rename_file(self, project, file, new_name, user):
        self.refresh_session()
        affected = self.s.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected.role == affected.role.Manager:
            file = self.s.query(File).get(file.id)
            file.name = new_name
            self.s.commit()
            return True
        else:
            return Error.PERMISSION_NOT_ALLOWED

    def rename_folder(self, project, folder, new_name, user):
        self.refresh_session()
        affected = self.s.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected.role == affected.role.Manager:
            folder = self.s.query(Folder).get(folder.id)
            folder.name = new_name
            self.s.commit()
            return True
        else:
            return Error.PERMISSION_NOT_ALLOWED

    def rename_snapshot(self, snapshot: Database, new_name: str, project: Project, user: User):
        affected = self.s.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected.role == affected.role.Manager:
            snapshot = self.s.query(Database).get(snapshot.id)
            snapshot.name = new_name
            self.s.commit()
            return True
        else:
            Error.PERMISSION_NOT_ALLOWED

    def select_file(self, id: int) -> File:
        """Returns the file corresponding to the id passed in parameter
        :param id: id of file
        :return: File
        """
        return self.s.query(File).get(id)

    def select_folder(self, id: int) -> Folder:
        """
        Returns the folder corresponding to the id passed in parameter
        :param id: id of folder
        :return: Folder
        """
        return self.s.query(Folder).get(id)

    def select_file_by_project(self, project_id: int, user):
        error = None
        if not user.can_read_project(self.s, user,
                                     self.s.query(Project).get(project_id)): error = Error.PERMISSION_NOT_ALLOWED
        return error, self.s.query(File).filter(File.project_id == project_id).all()

    def update_project_name(self, project: Project, new_name: str):
        """Update a project with the given new name."""
        project.name = new_name
        self.s.commit()

    def insert_database(self, database, user):
        """Insert a new database into the database."""
        file = self.s.query(File).filter(File.id == database.file_id).first()
        project = self.select_project_of_entity(file)
        can_create = User.can_create_file(self.s, user, project)
        if can_create:
            database.file = file
            self.s.add(database)
            self.s.commit()
            return None, database
        return Error.PERMISSION_NOT_ALLOWED, None

    def update_file_information(self, file_id, name, hash, is_64bit, ftype) -> None:
        """
        @param file: the file to update
        @type file: File
        @param name: name of file
        @type name: str
        @param hash: hash of file
        @type hash: str
        @param is_64bit: is 64 bit idb
        @type is_64bit: bool
        """
        self.refresh_session()
        file = self.s.query(File).get(file_id)
        file.file = name
        file.hash = hash
        file.is_64bit = is_64bit
        file.ftype = ftype
        self.s.commit()

    def select_database(self, id: int, user: User):
        """Select the database with the given id."""
        error = None
        database = self.s.query(Database).filter(Database.id == id).first()
        project = self.select_project_of_entity(database)
        if not User.can_read_project(self.s, user, project): return Error.PERMISSION_NOT_ALLOWED, None
        return error, database

    def select_databases(self, file_id, user) -> Tuple[Optional[Error], Database]:
        """Select the databases with the given project and name if user has read permission."""
        error = None
        file = self.s.query(File).get(file_id)
        project = self.select_project_of_entity(file)
        can_read = User.can_read_project(self.s, user, project)
        if not can_read: return Error.PERMISSION_NOT_ALLOWED, None
        databases = self.s.query(Database).filter(Database.file_id == file_id).all()
        return error, databases

    def insert_event(self, client, event: Event, user: User) -> None:
        """Insert a new event into the database."""
        dct = DefaultEvent.attrs(event.__dict__)
        database = self.s.query(Database).filter(Database.id == client.database_id).limit(1).all()[0]
        event = Event(tick=event.tick, dict=json.dumps(dct), database=database, user_id=user.id)
        self.s.add(event)
        self.s.commit()

    def update_comments(self, database_id: id, comment: str) -> None:
        database = self.s.query(Database).get(database_id)
        database.comments = comment
        self.s.commit()


    def select_events(self, database_id: id, tick: int):
        """Get all events sent after the given tick count."""
        events = self.s.query(Event).filter(Event.database_id == database_id).filter(Event.tick > tick).order_by(
            Event.tick.asc()).all()
        events_return = []
        for result in events:
            dct = json.loads(result.dict)
            dct["tick"] = result.tick
            events_return.append(DefaultEvent.new(dct))
        return events_return

    def last_tick(self, database_id: int) -> int:
        """Get the last tick of the specified project and database.
        :param database_id: The Database id
        :type database_id: int
        :return: the last tick number
        :rtype: int
        """

        result = self.s.query(Event).filter(Event.database_id == database_id).order_by(Event.tick.desc()).all()
        return result[0].tick if len(result) > 0 else 0

    def user_exist(self, username: str) -> bool:
        """
        Check if user exist
        :param username:
        :type username: str
        :return: True if user exist else False
        :rtype:  bool
        """
        if self.select_user_by_username(username) is None:
            return False
        return True

    def modify_last_connection(self, user: User) -> None:
        """
        Change last login field in User table
        """
        self.logger.debug("Change last connection field for  user %s " % user.username)
        self.refresh_session()
        user = self.s.query(User).get(user.id)
        user.last_login = datetime.datetime.now()
        self.s.commit()

    def register_user_ldap(self, username: str, email: Optional[str] = None):
        """"
        Register new user and affects permissions
        """
        self.refresh_session()
        date_format = "%Y/%m/%d"
        date = datetime.datetime.now().strftime(date_format)
        user = User(username=username, email=email, is_superuser=False, date_joined=date, ldap_user=True,
                    authentificationByPassword=False, password="None")
        # Update permission in project
        projects = self.s.query(Project).filter(Project.restricted == False).all()
        for project in projects:
            permission = Affected(user=user, projects=project, role=Affected.Role.Reader)
            self.s.add(permission)
        self.s.add(user)
        self.s.commit()

    def update_email(self, user: User, email: str) -> None:
        user.email = email
        self.s.commit()

    def select_user_by_email(self, email: str) -> Optional[User]:
        """
        Select user by email
        :param email:
        :return: User
        """
        user = self.s.query(User).filter(User.email == email).first()
        return user

    def select_user_by_username(self, username: str) -> Optional[User]:
        """
        Select user by username
        :param username:
        :type username: str
        :return: user correspond to username
        :rtype: User
        """
        user = self.s.query(User).filter(User.username == username).first()
        return user

    def get_hash_user(self, username: str) -> Tuple[str, str]:
        """
        Return the hash from Django database
        It's composed <digest>$<iterations>$<salt>$<hash>
        :param username:
        :return tuple:
        """
        password = self.s.query(User).filter(User.username == username).first().password
        return password.split('$')

    def update_notepad(self, database_id: id, text: str) -> bool:
        self.refresh_session()
        """Update database notepad contents"""
        database = self.s.query(Database).get(database_id)
        database.notepad = text
        self.s.commit()
        self.s.close()
        self.channel.send_modification_notepad(database_id)
        return True

    def select_notepad(self, database_id: int) -> Database:
        """Return the content of notepad"""
        return self.s.query(Database).get(database_id).notepad

    def select_entity_by_id_and_type(self, entity_id, entity_type):
        """Select entity by id and type corresponding"""
        if entity_type == "Project":
            return self.s.query(Project).get(entity_id)
        elif entity_type == "File":
            return self.s.query(File).get(entity_id)
        elif entity_type == "Folder":
            return self.s.query(Folder).get(entity_id)
        elif entity_type == "Database":
            return self.s.query(Database).get(entity_id)

    def retrieve_all_databases(self, object):
        """
        Retrieve all databases inside object
        """
        self.logger.debug("Handle retrieve all databases")
        databases = list()
        if isinstance(object, Database):
            databases.append(object)
            return databases
        elif isinstance(object, Folder) or isinstance(object, Project):
            _, subFolder, subFile = self.select_children(object)
            for folder in subFolder:
                databases += self.retrieve_all_databases(folder)
            for file in subFile:
                sub_databases = self.s.query(Database).filter(Database.file == file).all()
                databases += sub_databases
        elif isinstance(object, File):
            sub_databases = self.s.query(Database).filter(Database.file == object).all()
            databases += sub_databases
        return databases

    def select_children(self, entity):
        """
        Select and return children for a entity
        :return: tuple(List<Folder>,List<File>)
        :param entity: Object for wich children are sought
        """
        if isinstance(entity, Project):
            childrens_file = self.s.query(File).filter(File.project == entity).all()
            childrens_folder = self.s.query(Folder).filter(Folder.project == entity).all()
            return None, childrens_folder, childrens_file
        elif isinstance(entity, Folder):
            childrens_file = self.s.query(File).filter(File.folder == entity).all()
            childrens_folder = self.s.query(Folder).filter(Folder.parent_folder_id == entity.id).all()
            return None, childrens_folder, childrens_file

    def setRole(self, project: Project, user, new_role):
        # retrieve role and change them
        affected = self.s.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        affected.role = new_role
        self.s.commit()

    def remove_all_users_affected_to_project(self, project: Project, user: User):
        """
        Remove all users affected with reader or analyst role to the project
        @param project: project
        @type project: Project
        @param user: user want to remove all users
        @type user: User
        """
        self.logger.debug("Handle remove_all_users_affected_to_project ")
        affecteds = self.s.query(Affected).filter(Affected.role != Affected.Role.Admin) \
            .filter(Affected.user != user). \
            filter(Affected.projects == project).all()
        for affected in affecteds:
            if affected.role in (Affected.Role.Reader, Affected.Role.Analyst):
                affected.role = Affected.Role.Nill
        self.s.commit()

    def select_project_of_entity(self, entity) -> Project:
        """
        Retrieve project of entity
        :param entity:
        :return: Project
        """
        if isinstance(entity, Database):
            return self.select_project_of_entity(entity.file)
        if isinstance(entity, File):
            if entity.folder:
                return self.select_project_of_entity(entity.folder)
            elif entity.project:
                return entity.project
        elif isinstance(entity, Folder):
            if entity.project:
                return entity.project
            elif entity.parent_folder_id:
                entity = self.s.query(Folder).get(entity.parent_folder_id)
                return self.select_project_of_entity(entity)
        elif isinstance(entity, Project):
            return entity

    def insert_folder(self, folder_name, user, parent_type, parent_id):
        """Insert folder in database"""
        self.s = self.Session()
        parent = self.select_entity_by_id_and_type(parent_id, parent_type)
        project = self.select_project_of_entity(parent)
        can_create = User.can_create_file(self.s, user, project)
        if can_create:
            if isinstance(parent, Folder):
                folder = Folder(name=folder_name, parent_folder_id=parent.id)
            else:
                folder = Folder(name=folder_name, project=parent)
            self.s.add(folder)
            self.s.commit()
            self.s.close
            return None, folder
        else:
            self.s.close()
            Error.PERMISSION_NOT_ALLOWED, None

    def select_permissions(self, user: User):
        """Retrieve all permissions of user and return them"""
        permissions = self.s.query(Affected).filter(Affected.user == user).all()
        return permissions

    def get_all_databases(self):
        """Return all snapshot """

        databases = self.s.query(Database).all()
        self.s.close()
        return databases

    def select_all_permission_reader_analyst_for_project(self, project: Project):
        """Returns all affecteds user with role reader or analyst on the project"""
        permissions = self.s.query(Affected).filter(Affected.projects == project).filter(or_(
            Affected.role == Affected.Role.Reader, Affected.role == Affected.Role.Analyst)).all()
        return permissions

    def set_authenticiation_by_ldap(self, value: bool) -> None:
        self.refresh_session()
        setting = self.s.query(Setting).first()
        setting.authentification_ldap = value
        self.s.commit()

    def select_user_work_on_databases(self, databases: List[Database]):
        """

        :param databases:
        :return:
        """
        locks = list()
        for database in databases:
            lock_on_db = self._select_user_work_on_database(database)
            if lock_on_db is not None:
                locks = [*locks, *lock_on_db]
        return locks

    def _select_user_work_on_database(self, database: Database) -> Optional[Lock]:
        """"
        return all users locks on database
        """
        locks = self.s.query(Lock).filter(Lock.database_id == database.id).all()
        if bool(locks):
            return [lock.user for lock in locks]
        return None

    def insert_lock(self, user: Union[User, int], database: Union[Database, int]) -> None:
        """
        When a user open a database a lock is created
        :param user:
        :param database:
        """
        database_id = database.id if isinstance(database, Database) else database
        user_id = user.id if isinstance(user, User) else user
        lock = Lock(user_id=user_id, database_id=database_id)
        self.s.add(lock)
        self.s.commit()

    def remove_lock(self, user: User, database: Union[Database, int]) -> None:
        """
        Remove lock when a
        :param user:
        :param database:
        """
        if database is None or user is None:
            return
        database_id = database.id if isinstance(database, Database) else database
        lock = self.s.query(Lock).filter(Lock.user_id == user.id).filter(Lock.database_id == database_id).first()
        if lock is not None:
            self.s.delete(lock)
            self.s.commit()
