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
import re

import bleach
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import User
from django.forms import model_to_dict
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.html import escape
from django.views.decorators.http import require_POST, require_GET, require_http_methods

from IDArling.models import Projects
from IDArling_Management import BackendAuthentification
from IDArling_Management.utils.Utils_Data import UtilsData

User = get_user_model()


@require_GET
@login_required
@permission_required('User.delete_user')
def index(request):
    users = [model_to_dict(user, fields=['last_login', 'id', 'is_superuser', 'username', 'authentificationByPassword',
                                         'ldap_user']) for user in User.objects.all()]
    # escape
    for user in users:
        user['username'] = escape(user['username'])
    params = {"users": users}

    return render(request, 'management.html', params)


@require_POST
@permission_required('User.delete_user')
def delete_user(request):
    """
    Delete user
    :param request:
    :return: ok if user can delete else error
    """
    # get user to delete
    user_id = request.POST.get('id_user')
    user_to_delete = User.objects.get(pk=user_id)
    if user_to_delete.is_superuser:
        return HttpResponse(json.dumps("error you can't delete admin"),
                            content_type="application/json")
    else:
        user_to_delete.delete()
        return HttpResponse(json.dumps("ok"),
                            content_type="application/json")


@require_http_methods(["GET", "POST"])
@login_required
@permission_required('User.add_user')
def create_user(request):
    if request.method == 'GET':
        return render(request, 'createUser.html')
    elif request.method == 'POST':
        error = list()
        username = bleach.clean(request.POST['username'])
        if not re.match("^[a-zA-Z0-9_.-@{1}]+$", username):
            error.append("Enter a valid username. This value may contain only letter, . and @ ")
            return render(request, 'createUser.html', {"error": error})
        password = request.POST['password']
        try:
            password_validation.validate_password(password)
        except Exception as e:
            if "error_list" in e.__dict__:
                for i in e.error_list:
                    error.append(i.message)
            else:
                error.append(e.message)
            return render(request, 'createUser.html', {"error": error})
        user, retour = BackendAuthentification.BackendAuthentification.create_user(username=username, password=password)
        # Set permissions for user
        if not bool(error):
            user.set_create_default_permissions()
        print("retour is : " + str(retour))
        return render(request, 'createUser.html', retour)


@require_GET
@login_required
def project_mangament(request):
    users = User.objects.all()
    if request.method == 'GET':
        return render(request, 'projects.html', {"users": users})


"""
def test(user):
    projects = Projects.objects.all()
    projects_to_return = list()
    for project in projects:
        affectation = Affecteds.objects.filter(projects=project, user=user).first()
        if affectation is not None and affectation.role in (
                Affecteds.ROLE.Manager, Affecteds.ROLE.Reader, Affecteds.ROLE.Analyst, Affecteds.ROLE.Admin):
            projects_to_return.append(project)
    return projects_to_return
"""


@require_GET
@login_required
def ajax_list_tree(request):
    """Send all project tree for display in front
    @see : /management/project/
    """
    user = request.user
    projects = Projects.objects.all()
    tree = list()
    for project in projects:
        try:
            if request.user.can_read_project(project):
                tree.append(project.get_tree_children(user))
        except Exception as e:
            print("Exception is " + str(e))
    return HttpResponse(json.dumps(tree, default=UtilsData.default), content_type='application/json')
