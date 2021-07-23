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
import logging
import os

from django.contrib.auth import get_user_model
from django.contrib.auth import login as django_login, password_validation
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.forms import model_to_dict
from django.shortcuts import redirect
from django.shortcuts import render
from django.views.decorators.http import require_POST, require_GET, require_http_methods

from IDArling.models import User, Settings
from ..BackendAuthentification import BackendAuthentification

logger = logging.getLogger(__name__)
User = get_user_model()


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view servlet
    :see login.html
    :param request:
    :type request: Request
    :return: httpResponse
    :rtype:HttpResponse
    """
    try:
        context = model_to_dict(Settings.objects.first())
    except Exception:
        authentification_by_ldap = True
        authentification_by_username_password = True

        if os.environ.get("AUTHENTIFICATION_BY_LDAP") != "True":
            authentification_by_ldap = False
        if os.environ.get("AUTHENTIFICATION_BY_USERNAME_PASSWORD") != "True":
            authentification_by_username_password = False
        logger.info(f"Settings save with : "
                    f"authentification_ldap = {authentification_by_ldap}"
                    f"& authentification_username_password = {authentification_by_username_password} ")
        setting = Settings(authentification_ldap=authentification_by_ldap,
                           authentification_username_password=authentification_by_username_password)
        setting.save()
    finally:
        context = model_to_dict(Settings.objects.first())
        context["error"] = None
        if request.method == 'GET':
            logger.info(f"context is {context}")
            return render(request, 'login.html', context)
        elif request.method == 'POST':
            username = request.POST.get("username", "")
            password = request.POST.get("password", "")
            logger.info(f"Try to autenticate user {username}")
            user = BackendAuthentification.authenticate(username=username, password=password)
            if user is not None:
                django_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return redirect('/accounts/')
            else:
                context["error"] = "bad credentials"
                return render(request, 'login.html', status=400, context=context)


@require_GET
@login_required
def logout_view(request):
    """
    Logout current user
    :rtype: HttpResponse
    """
    logout(request)
    return redirect('/login')


@require_GET
@login_required
def account_view(request):
    """Account servlet, where user can change password"""
    user = request.user
    idarling_user = User.objects.get(username=request.user.username)
    return render(request, 'account.html', {"idarling_user": idarling_user,
                                            "error":None})


@require_POST
@login_required
def synchronise_account(request):
    """the user can synchronize his LDAP account by creating a password with which he can log in"""
    # Check if account username doesnt exist
    idarling_user = User.objects.get(username=request.user.username)
    if idarling_user.authentificationByPassword == False:
        new_password = request.POST.get("newPassword", "")
        new_password_verify = request.POST.get("newPasswordVerify", "")
        try:
            validate_password = password_validation.validate_password(new_password)
        except Exception as e:
            error = list()
            if "error_list" in e.__dict__:
                for i in e.error_list:
                    error.append(i.message)
            else:
                error.append(e.message)
            return render(request, 'account.html', {"error": error})
        if new_password == new_password_verify:
            request.user.set_password(new_password)
            idarling_user.authentificationByPassword = True
            idarling_user.save()

    return render(request, 'account.html', {"idarling_user": idarling_user})


@require_POST
@login_required
def change_password(request):
    """Change password view"""
    idarlingUser = request.user
    oldPassword = request.POST.get("oldPassword", "")
    newPassword = request.POST.get("newPassword", "")
    newPasswordVerify = request.POST.get("newPasswordVerify", "")
    wrong_password = request.user.check_password(oldPassword)
    try:
        validate_password = password_validation.validate_password(newPassword)
    except Exception as e:
        context = {"error": list()}
        if "error_list" in e.__dict__:
            for i in e.error_list:
                context["error"].append(i.messages[0])
        else:
            context["error"].append(e.message)
        return render(request, 'account.html', context=context)
    identical_new_password = (newPassword == newPasswordVerify)
    if wrong_password and identical_new_password:
        request.user.set_password(newPassword)
        request.user.save()
    else:
        context = {"error": list()}
        context["idarling_user"] = idarlingUser
        if not wrong_password:
            context["error"].append("Wrong password")
        if not identical_new_password:
            context["error"].append("Passwords are not identical")
        return render(request, 'account.html', context=context)
    return render(request, 'account.html')
