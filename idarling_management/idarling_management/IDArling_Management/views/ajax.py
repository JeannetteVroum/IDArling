#
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
import json
import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.forms import model_to_dict
from django.http import HttpResponse
from django.utils.html import escape
from django.views.decorators.http import require_GET, require_POST

from IDArling.models import User, Projects, Affecteds, Files, Folders, Events, Lock
from IDArling_Management.utils.Utils_Data import UtilsData

User = get_user_model()

# Get an instance of a logger
logger = logging.getLogger(__name__)


@login_required
@require_GET
def get_database_from_file(request, id_file: int):
    """Returns databases include in files"""
    # check if user can access to the project
    logger.info("User %s select files %d" % (request.user.username, id_file))
    file = UtilsData.get_object_by_type_and_id('file', id_file)
    project = request.user.get_parent(file)
    return_databases = list()
    can_write = request.user.can_write(project)
    if request.user.can_read_project(project):
        databases = file.databases_set.all()
        for database in databases:
            d = dict()
            qs = Lock.objects.filter(database=database)
            d["used"] = True if qs.exists() else False
            d["id"] = database.id
            d["name"] = escape(database.name)
            d["date"] = escape(database.date)
            d["comment"] = escape(database.comments)
            d["can_write"] = can_write
            ticks = Events.objects.filter(database_id=database.id).aggregate(Max('tick'))['tick__max']
            d["tick"] = ticks if ticks is not None else -1
            return_databases.append(d)
    return HttpResponse(json.dumps(return_databases, default=UtilsData.default),
                        content_type="application/json")


@require_POST
@login_required
def create_file(request):
    id_entity = request.POST.get('id_entity')
    type_entity = request.POST.get('type')
    entity = UtilsData.get_object_by_type_and_id(type_entity, id_entity)
    if (request.user.can_create_file(entity)):
        if isinstance(entity, Folders):
            file = Files.objects.create(folder=entity, name="none")
        elif isinstance(entity, Projects):
            file = Files.objects.create(project=entity, name="none")
        return HttpResponse(json.dumps(model_to_dict(file), default=UtilsData.default),
                            content_type="application/json")
    return HttpResponse(json.dumps({"error": "You don't have the permission to create file in this project"}),
                        content_type="application/json")


@require_POST
@login_required
def project_management(request):
    action = request.POST.get('action')
    user = request.user

    if action == "create_project":
        project = Projects.create_project(user, restricted=False)
    elif action == 'create_project_restricted':
        project = Projects.create_project(user, restricted=True)
    else:
        return HttpResponse(json.dumps("error"),
                            content_type="application/json")
    ##Apply role
    logger.info("User %s create new project with id %d" % (request.user.username, project.id))
    return HttpResponse(json.dumps(model_to_dict(project), default=UtilsData.default),
                        content_type="application/json")


@require_POST
@login_required
def project_management_rename(request):
    id_entity = request.POST.get("id")
    type_entity = request.POST.get("type")
    name = request.POST.get('name')
    if id_entity is None or type_entity is None or name is None:
        return HttpResponse(json.dumps("Error parameters"),
                            content_type="application/json")
    object = UtilsData.get_object_by_type_and_id(type_entity, id_entity)
    user = request.user
    if user.can_modify(object):
        """Rename project and send notification"""
        object.name = escape(name)
        object.save()
        logger.info(
            "User %s rename %s with id %d into %s" % (user.username, object.__class__.__name__, object.id, object.name))
        return HttpResponse(json.dumps("Ok"),
                            content_type="application/json")
    else:
        logger.info("User %s rename %s with id %d into %s without permission" % (
            user.username, object.__class__._name__, object.id,
            object.name))
        return HttpResponse(json.dumps("Don't have the permission to rename"),
                            content_type="application/json")


def list_user_project(request, type, id_project):
    logger.info("User %s try to list user's project with id %d" % (request.user.username, id_project))
    object = UtilsData.get_object_by_type_and_id(type, id_project)
    if object is None:
        logger.error("Object %s with id %d does not exist " % (type, id_project))
        return HttpResponse(json.dumps("Error parameters"),
                            content_type="application/json")
    can_affect = request.user.can_affect(object)
    if can_affect:
        users_role = object.get_roles()
        return HttpResponse(json.dumps(users_role),
                            content_type="application/json")
    return HttpResponse(json.dumps("error"),
                        content_type="application/json")


@require_POST
@login_required
def remove_all_users(request):
    """Remove all users affecteds in the project"""
    id_project = request.POST.get("project_id")
    project = UtilsData.get_object_by_type_and_id("project", id_project)
    if request.user.can_delete(project):
        roles = project.affecteds_set.all()
        for role in roles:
            if role.role not in (Affecteds.ROLE.Manager, Affecteds.ROLE.Admin):
                role.role = Affecteds.ROLE.Nill
                role.save()
        return HttpResponse(json.dumps("Ok"),
                            content_type="application/json")
    else:
        logger.error("user %s try to remove all users to project %d  " % (request.user.username, id_project))
        return HttpResponse(json.dumps("error"),
                            content_type="application/json")


@require_POST
@login_required
def set_user_role(request):
    """
    Set user role
    used in
    :param request:
    :return: Ok
    """
    id_user = request.POST.get('user_id')
    role = request.POST.get('role')
    id_projet = request.POST.get('project_id')
    # retrieves the user whose role needs to be changed
    user_to_modify = User.objects.get(pk=id_user)
    # check if user can attribute role for the project
    project = UtilsData.get_object_by_type_and_id('project', id_projet)
    if request.user.can_affect(project):
        # Verifies if the user whose role is to be changed is the administrator
        if user_to_modify.is_superuser:
            return HttpResponse(json.dumps("error you can't remove admin role"),
                                content_type="application/json")
        else:
            # change role
            project.setRole(user_to_modify, role)
    return HttpResponse(json.dumps("ok"),
                        content_type="application/json")


@require_GET
@login_required
def get_roles(request):
    """
    :param request:
    :return: HttpResponse json of all roles available
    """
    roles = Affecteds.role_verbose()
    return HttpResponse(json.dumps(roles),
                        content_type="application/json")


@login_required
@require_POST
def remove(request):
    id_entity = request.POST.get('id_entity')
    type_entity = request.POST.get('type_entity')
    entity = UtilsData.get_object_by_type_and_id(type_entity, id_entity)
    project = request.user.get_parent(entity)
    can_delete, error = request.user.can_delete(project)
    if can_delete:
        entity.delete()
        logger.info("User %s delete object %s " % (escape(request.user.username), entity))
        return HttpResponse(json.dumps("ok"), content_type="application/json")
    logger.warning("User %s try to delete  %s with error %s " % (escape(request.user.username), entity, error))
    return HttpResponse(json.dumps(error), content_type="application/json")


@login_required
@require_POST
def create_folder(request):
    id_entity = request.POST.get('id_entity')
    parent_type = request.POST.get('parent_type')
    # Check if user have permission to write in project
    parent = UtilsData.get_object_by_type_and_id(parent_type, id_entity)
    can_write = request.user.can_create_file(parent)
    logger.info("User %s try to create a new folder " % request.user.username)
    if can_write:
        # create new folder and join it to project
        if isinstance(parent, Projects):
            folder = Folders.objects.create(name="None", project=parent)
        elif isinstance(parent, Folders):
            folder = Folders.objects.create(name="None")
            parent.folders_set.add(folder)
        return HttpResponse(json.dumps(model_to_dict(folder), default=UtilsData.default),
                            content_type="application/json")
    return HttpResponse(json.dumps("ok"), content_type="application/json")
