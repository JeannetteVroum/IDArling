from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import User, PermissionsMixin
from django.db import models
from django.forms import model_to_dict
from django.utils.html import escape
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _
from model_utils import Choices

from .manager import UserManager


# Create your models here.


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(_('username'), max_length=30, blank=False, unique=True,
                                error_messages={
                                    'unique': _("The username is already taken."),
                                })
    email = models.EmailField(
        _('Email Address'), unique=True, null=True,
        error_messages={
            'unique': _("A user with that email already exists."),

        }
    )

    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
    objects = UserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    ldap_user = models.BooleanField(default=False)
    authentificationByPassword = models.BooleanField(default=False)

    class Meta(object):
        db_table = 'User'
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        abstract = False

    def can_create_file(self, project):
        if self.is_superuser:
            return True
        role = project.affecteds_set.filter(user=self).first()
        if role.role in (Affecteds.ROLE.Manager, Affecteds.ROLE.Admin):
            return True
        return False

    def __str__(self):
        return self.username

    def can_delete(self, object):
        """

        :param object:
        :return: Error
        """
        error = {"error": list()}
        if isinstance(object, Files):
            project = object.project
        elif isinstance(object, Databases):
            project = object.file.project
        else:
            project = object
        role = project.affecteds_set.get(user=self)
        if not (role.role in (Affecteds.ROLE.Manager, Affecteds.ROLE.Admin)):
            error["error"].append("Don't have the permission to delete this.")
            return False, error
        else:
            # Retrieves all users assigned to the project,
            # if an analyst or a reader is assigned to the project then returns false with an error message.
            roles = Affecteds.objects.filter(projects=project)
            for role in roles:
                if role.role == Affecteds.ROLE.Reader or role.role == Affecteds.ROLE.Analyst:
                    error["error"].append("Cannot delete."
                                          "A user is assigned to the project either with the role reader or the role analyst. ")
                    return False, error
        return True, None

    def can_read(self, object):
        """
        Return True if user can read project else False
        """
        role = self.get_role(object)
        if role in (Affecteds.ROLE.Admin, Affecteds.ROLE.Analyst, Affecteds.ROLE.Reader,
                    Affecteds.ROLE.Manager):
            return True
        return False

    def can_modify(self, object):
        """
        Return True if user can modify project( set name)
        """
        role = self.get_role(object)
        if role in (Affecteds.ROLE.Admin, Affecteds.ROLE.Analyst,
                    Affecteds.ROLE.Manager):
            return True
        return False

    def can_write(self, object):
        """
        Return true if user is manager or analyst
        """
        role = self.get_role(object)
        if role in (Affecteds.ROLE.Manager, Affecteds.ROLE.Analyst):
            return True
        return False

    def get_parent(self, object):
        """Return project for a objet"""
        if isinstance(object, Projects):
            return object
        elif isinstance(object, Files):
            if object.project: return object.project
            return self.get_parent(object.folder)
        elif isinstance(object, Folders):
            if object.project: return object.project
            return self.get_parent(object.parent_folder)
        elif isinstance(object, Databases):
            return self.get_parent(object.file)

    def get_role(self, object):
        """
        return the role of the user for the object passed in parameter
        :param object:
        :return: Affected.Role
        """
        project = self.get_parent(object)
        role = project.affecteds_set.filter(user=self).first()
        return role.role

    def set_create_default_permissions(self):
        """Set default permissions when user is created"""
        projects = Projects.objects.all()
        for project in projects:
            if not project.restricted:
                Affecteds.objects.create(projects=project, user=self, role=Affecteds.ROLE.Reader)

    def can_read_project(self, project):
        """Check permission if user can read the project"""
        try:
            role = project.affecteds_set.get(user=self)
        except Exception:
            if project.restricted:
                return Affecteds.objects.create(user=self, projects=project, role=Affecteds.ROLE.Nill)
            else:
                return Affecteds.objects.create(user=self, projects=project, role=Affecteds.ROLE.Readere)
        return role.role in (
            Affecteds.ROLE.Manager, Affecteds.ROLE.Admin, Affecteds.ROLE.Reader, Affecteds.ROLE.Analyst)

    def can_affect(self, object):
        if (isinstance(object, Projects)):
            # search if user is affected to project
            role = object.affecteds_set.filter(user=self).first()
            return role.role in (Affecteds.ROLE.Manager, Affecteds.ROLE.Admin)


class Projects(models.Model):
    name = models.CharField(max_length=250, blank=True, null=True)
    date = models.DateTimeField(default=now)
    restricted = models.BooleanField(default=False, null=False)

    class Meta:
        db_table = 'projects'

    def get_roles(self):
        users = [model_to_dict(user, fields=['username', 'id', 'is_superuser']) for user in User.objects.all()]
        for user in users:
            try:
                role = self.affecteds_set.get(user_id=user['id'])
                if role is not None:
                    user['role'] = role.role
                else:
                    if self.restricted:
                        Affecteds.objects.create(user_id=user["id"], projects=self, role=Affecteds.ROLE.Nill)
                        user['role'] = 'Nill'
                    else:
                        Affecteds.objects.create(user_id=user["id"], projects=self, role=Affecteds.ROLE.Reader)
                        user['role'] = 'Reader'
            except Affecteds.DoesNotExist:
                if user['is_superuser']:
                    Affecteds.objects.create(user_id=user['id'], projects=self, role=Affecteds.ROLE.Admin)
                    user['role'] = 'Admin'
                elif not self.restricted:
                    Affecteds.objects.create(user_id=user['id'], projects=self, role=Affecteds.ROLE.Reader)
                    user['role'] = 'Reader'
                else:
                    user['role'] = 'None'
        return users

    def setRole(self, user, new_role):
        # retrieve role and change them
        try:
            affectation = Affecteds.objects.get(user=user, projects=self)
            affectation.setRole(new_role)
        except Affecteds.DoesNotExist:
            Affecteds.objects.create(user=user, projects=self, role=new_role)

    @staticmethod
    def create_project(creator, name="None", restricted=False):
        """Create new project and apply roles"""
        project = Projects.objects.create(name=name, restricted=restricted)
        if creator.is_superuser:
            Affecteds.objects.create(projects=project, user=creator, role=Affecteds.ROLE.Admin)
        else:
            Affecteds.objects.create(projects=project, user=creator, role=Affecteds.ROLE.Manager)
        users = User.objects.all()
        for user in users:
            if user != creator and not user.is_superuser:
                if restricted:
                    Affecteds.objects.create(projects=project, user=user, role=Affecteds.ROLE.Nill)
                else:
                    Affecteds.objects.create(projects=project, user=user, role=Affecteds.ROLE.Reader)
            elif user.is_superuser and user != creator:
                Affecteds.objects.create(projects=project, user=user, role=Affecteds.ROLE.Admin)
        return project

    def get_children(self):
        """Retrieves children of project (files+folder) and return them"""
        folders_children = list(self.folders_set.all())
        files_children = list(self.files_set.all())
        joined_children = folders_children + files_children
        return list(joined_children)

    def get_tree_children(self, user: User):
        """Retrieves children of project (files+folder) and return them in dict"""
        project = model_to_dict(self, fields=['id', 'name', 'date', 'restricted'])
        project["type"] = "project"
        project["title"] = escape(project["name"])
        project["folder"] = True
        project["role"] = user.get_role(self)
        folders_children = self.folders_set.all()
        files_folder = self.files_set.all()
        project["children"] = list()
        for folder in folders_children:
            project["children"].append(folder.get_tree_children(project["role"]))
        for file in files_folder:
            project["children"].append(file.get_tree_children(project["role"]))
        return project


class Affecteds(models.Model):
    ROLE = Choices('Admin', 'Manager', 'Analyst', 'Reader', 'Nill')
    role = models.CharField(choices=ROLE, default=ROLE.Reader, max_length=10)
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name='assigned', null=False)
    projects = models.ForeignKey(Projects, on_delete=models.CASCADE, null=False)

    @staticmethod
    def role_verbose():
        return list(dict(Affecteds.ROLE).keys())

    class Meta:
        db_table = 'affecteds'

    def setRole(self, new_role):
        self.role = new_role
        self.save()


class Folders(models.Model):
    name = models.CharField(max_length=250, blank=True, null=False)
    parent_folder = models.ForeignKey('self', on_delete=models.CASCADE, null=True)
    project = models.ForeignKey(Projects, models.CASCADE, null=True)

    class Meta:
        db_table = 'folders'

    def retrieve_project(self):
        """
        Retrieve project for current folder
        :return:
        """
        if self.project: return self.project
        parent_folder = self.parent_folder
        return parent_folder.retrieve_project()

    def get_tree_children(self, role):
        """Retrieve children of Folder and return them in dict"""
        dct = model_to_dict(self)
        folders_children = self.folders_set.all()
        dct["type"] = 'folder'
        dct["children"] = list()
        dct["title"] = escape(self.name)
        dct["folder"] = True
        dct["role"] = role
        for folder in folders_children:
            sub_folder = folder.get_tree_children(role)
            dct['children'].append(sub_folder)
        files_children = self.files_set.all()
        for file in files_children:
            dct['children'].append(file.get_tree_children(role))
        return dct


class Files(models.Model):
    name = models.CharField(max_length=250, blank=True, null=True)
    hash = models.CharField(max_length=50, blank=True, null=True)
    file = models.CharField(max_length=250, blank=True, null=True)
    ftype = models.CharField(max_length=50, blank=True, null=True)
    date = models.DateTimeField(default=now)
    project = models.ForeignKey(Projects, models.CASCADE, null=True)
    folder = models.ForeignKey(Folders, models.CASCADE, null=True)
    is_64bit = models.BooleanField(blank=True, null=True)

    class Meta:
        db_table = 'files'

    def get_tree_children(self, role):
        """Retrieve children of Files (databases) and return them"""
        dct = model_to_dict(self)
        dct['type'] = 'file'
        dct["title"] = escape(self.name)
        dct['folder'] = False
        dct['role'] = role
        return dct


class Databases(models.Model):
    date = models.DateTimeField(default=now)
    name = models.CharField(max_length=250, blank=True, null=True)
    tick = models.IntegerField(blank=True, null=True)
    file = models.ForeignKey(Files
                             , models.CASCADE)
    notepad = models.CharField(blank=True, max_length=1000, default="", null=True)
    comments = models.CharField(blank=True, max_length=1000, default="", null=True)

    class Meta:
        db_table = 'databases'


class Events(models.Model):
    tick = models.IntegerField(blank=True, null=True)
    dict = models.TextField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True)
    database = models.ForeignKey(Databases, models.CASCADE)

    class Meta:
        db_table = 'events'


class Settings(models.Model):
    authentification_ldap = models.BooleanField(null=False, default=True);
    authentification_username_password = models.BooleanField(null=False, default=True)

    class Meta:
        db_table = 'settings'


class Lock(models.Model):
    database = models.ForeignKey(Databases, models.CASCADE, null=False)
    user = models.ForeignKey(User, models.CASCADE, null=False)

    class Meta:
        db_table = "lock"
