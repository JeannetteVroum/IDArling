# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
import enum
from sqlalchemy import Column, Integer, String, Date, ForeignKey, DateTime, Boolean, Enum, PrimaryKeyConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
from .packets import Default

Base = declarative_base()


class Model(Default):
    """
    A model is an object that can be serialized and sent over the network, but 
    that can be saved into the SQL database used by the server.
    """

    def build(self, dct):
        self.build_default(dct)
        return dct

    def parse(self, dct):
        self.parse_default(dct)
        return self

    def __repr__(self):
        """
        Return a textual representation of the object. It will mainly be used
        for pretty-printing into the console.
        """
        attrs = u", ".join(
            [
                u"{}={}".format(key, val)
                for key, val in Default.attrs(self.__dict__).items()
            ]
        )
        return u"{}({})".format(self.__class__.__name__, attrs)


class Project(Base):
    __tablename__ = 'projects'

    __acceptable_keys_list = ['date', 'name', 'restricted', 'id']

    id = Column(Integer, primary_key=True)
    name = Column(String())
    date = Column(DateTime(True), nullable=False)
    restricted = Column(Boolean, nullable=False, default=False)

    files = relationship("File"
                         , back_populates="project",
                         cascade="all, delete",
                         passive_deletes=True)

    def __init__(self, **kwargs):
        [self.__setattr__(key, kwargs.get(key)) for key in self.__acceptable_keys_list]

    @staticmethod
    def convert_to_dict(project):
        """
        :param project:
        :return:
        """
        dct = dict()
        for key in Project.__acceptable_keys_list:
            if key != "date":
                dct[key] = vars(project).get(key)
            else:
                dct[key] = vars(project).get(key).__str__()
        return dct

    @staticmethod
    def dict_to_project(dct):
        project = Project()
        [project.__setattr__(key, dct["project"].get(key)) for key in Project.__acceptable_keys_list]
        return project


class User(Base):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True)
    password = Column(String(128), nullable=True)
    last_login = Column(DateTime(True))
    is_superuser = Column(Boolean, nullable=False)
    username = Column(String(30), nullable=False, unique=True)
    email = Column(String(254), unique=True)
    date_joined = Column(DateTime(True), nullable=False)
    ldap_user = Column(Boolean, nullable=False)
    authentificationByPassword = Column(Boolean, nullable=False)

    @staticmethod
    def can_create_file(session, user, project) -> bool:
        """

        Return True if user can create a file in the project
        """
        affected = session.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if bool(affected.role) and not (affected.role in (Affected.Role.Analyst, Affected.Role.Manager)):
            return False
        return True

    @staticmethod
    def can_read_database(session, user, project, id_database):
        affected = session.query(Affected).filter(Affected.user == user).filter(
            Affected.projects == project).first()
        if affected.role not in (Affected.Role.Analyst, Affected.Role.Manager, Affected.Role.Reader):
            return False
        return True

    @staticmethod
    def set_create_default_permissions(session,user):
        """Set default permissions when user is created"""
        projects = session.query(Project).filter(Project.restricted == False)
        for project in projects:
                session.add(Affected.objects.create(projects=project, user=user, role=Affected.ROLE.Reader))
                session.commit()
    @staticmethod
    def can_read_project(session, user, project):
        """
        Method return true if user can read the project
        :param session:
        :type session:
        :param user: user to test
        :type user: User
        :param project:
        :type project: Project
        :return: True if user can read else false
        :rtype: bool
        """
        affected = session.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected is None:
            # verify if project is reserved else create a affectation with reader role
            if not project.restricted:
                session.add(Affected(user=user, projects=project, role=Affected.Role.Reader))
                session.commit()
                return True
            else:
                session.add(Affected(user=user, projects=project, role=Affected.Role.Nill))
                session.commit()
                return False
        if bool(affected.role) and not (
                affected.role in (Affected.Role.Analyst, Affected.Role.Manager, Affected.Role.Reader)):
            return False
        return True

    @staticmethod
    def can_update_database(session, user, project):
        affected = session.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if not (affected.role in (Affected.Role.Analyst, Affected.Role.Manager, Affected.Role.Admin)):
            return False
        return True

    @staticmethod
    def can_modify_project(session, user, project: Project):
        """
        @param session:
        @type session:
        @param user: user
        @type user: User
        @param project: project
        @type project: Project
        @return: True if user is Admin or Manager
        @rtype: bool
        """
        affected = session.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        if affected.role in (Affected.Role.Admin, Affected.Role.Manager):
            return True
        return False

    @staticmethod
    def getRole(session, project: Project, user):
        affected = session.query(Affected).filter(Affected.user == user).filter(Affected.projects == project).first()
        return affected.role


class Setting(Base):
    __tablename__ = 'settings'

    id = Column(Integer, primary_key=True)
    authentification_ldap = Column(Boolean, nullable=False)
    authentification_username_password = Column(Boolean, nullable=False)


class Affected(Base):
    __tablename__ = 'affecteds'

    class Role(enum.Enum):
        Manager = "Manager"
        Admin = "Admin"
        Reader = "Reader"
        Analyst = "Analyst"
        Nill = "Nill"

    id = Column(Integer, primary_key=True)
    role = Column(Enum(Role))
    user_id = Column(ForeignKey('User.id', deferrable=True, initially='DEFERRED'), nullable=False, index=True)
    projects_id = Column(ForeignKey('projects.id', deferrable=True, initially='DEFERRED'), nullable=False, index=True)

    projects = relationship('Project')
    user = relationship('User')


class File(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    name = Column(String())
    hash = Column(String())
    file = Column(String())
    ftype = Column(String())
    date = Column(Date)
    is_64bit = Column(Boolean)
    project_id = Column(Integer,
                        ForeignKey('projects.id', ondelete="cascade"))
    folder_id = Column(Integer,
                       ForeignKey('folders.id', ondelete='cascade'))

    folder = relationship('Folder', back_populates="files")
    project = relationship('Project', back_populates='files')
    databases = relationship("Database",
                             back_populates="file",
                             cascade="all, delete",
                             passive_deletes=True)

    def __init__(self, id=None, name=None, hash=None, file=None, ftype=None, date=None, project_id=None, project=None,
                 folder_id=None, folder=None, is_64bit=None):
        self.name = name
        self.id = id
        self.hash = hash
        self.file = file
        self.ftype = ftype
        self.date = date
        self.project_id = project_id
        self.project = project
        self.folder = folder
        self.folder_id = folder_id
        self.is_64bit = is_64bit


class Database(Base):
    __tablename__ = 'databases'

    id = Column(Integer, primary_key=True)
    date = Column(DateTime(True))
    name = Column(String())
    tick = Column(Integer)
    file_id = Column(Integer,
                     ForeignKey('files.id', ondelete='CASCADE'))

    file = relationship('File', back_populates="databases")

    notepad = Column(String(1000), default='')
    comments = Column(String(1000), default='')

    def __init__(self, id=None, date=None, name=None, tick=None, file_id=None, file=None, comments=None):
        self.id = id
        self.date = date
        self.name = name
        self.tick = tick
        self.file_id = file_id
        self.file = file
        self.comments = comments


class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True)
    tick = Column(Integer)
    dict = Column(String())
    user_id = Column(ForeignKey('User.id', deferrable=True, initially="DEFERRED"), nullable=False, index=True)
    database_id = Column(ForeignKey('databases.id', deferrable=True, initially='DEFERRED'), nullable=True, index=True)
    user = relationship('User')
    database = relationship('Database')


class Folder(Base):
    __tablename__ = 'folders'
    id = Column(Integer, primary_key=True)
    name = Column(String())
    parent_folder_id = Column(ForeignKey('folders.id', ondelete='CASCADE'), nullable=True,
                              index=True)
    project_id = Column(ForeignKey('projects.id', ondelete='CASCADE'), nullable=True, index=True)
    project = relationship('Project')
    parent_folder = relationship('Folder')

    files = relationship("File",
                         back_populates="folder",
                         cascade="all, delete",
                         passive_deletes=True)


class Lock(Base):
    __tablename__ = 'lock'
    __table_args__ = (
        PrimaryKeyConstraint('database_id', 'user_id'),
    )
    database_id = Column(Integer, ForeignKey('databases.id'))
    user_id = Column(Integer, ForeignKey('User.id'))

    database = relationship('Database', lazy='joined')
    user = relationship('User', lazy='joined')
