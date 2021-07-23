"""IDArling_Management URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings as django_settings
from django.conf.urls.static import static
# from django.contrib import admin
from django.urls import path

from .views import account, home, management, ajax, settings, database

urlpatterns = [
                  #    path('admin/', admin.site.urls),
                  path('', management.project_mangament, name="home"),
                  # Redirect to /account
                  path('home', home.home, name='home'),
                  # Login page
                  path('accounts/login/', account.login_view, name='login'),
                  # Login page
                  path('login', account.login_view, name='login'),
                  # User in this page can change password
                  path('accounts/', account.account_view, name='account'),
                  # Logout page
                  path('accounts/logout/', account.logout_view, name='logout'),
                  # Synchronise normal account with ldap
                  path('accounts/synchronise_account', account.synchronise_account, name='synchronise_account'),
                  path('accounts/change_password', account.change_password, name='change_password'),
                  # Only access for admin user (Delete user)
                  path('management', management.index, name='management'),
                  # Delete user
                  path('management/delete_user', management.delete_user, name='delete_user'),
                  path('management/project/', management.project_mangament, name="management_project"),
                  path('management/user/create', management.create_user, name="create_user"),
                  path('ajax/list_tree', management.ajax_list_tree, name="list_tree"),
                  # Get database include in file
                  path('ajax/file/database/<int:id_file>', ajax.get_database_from_file, name="get_database_from_file"),
                  # return all roles availables
                  path('ajax/get_roles', ajax.get_roles, name="get_roles"),
                  # changes the role of a user for the given project
                  path('ajax/set_role', ajax.set_user_role, name="set_user_role"),
                  # Magement project ajax, actions : create projects, affect rôle etc.
                  path('ajax/management/project/', ajax.project_management, name="management_project_ajax"),
                  # Rename project/files/idb
                  path('ajax/project/rename/', ajax.project_management_rename, name="management_project_rename"),
                  # Remove all users affected to project
                  path('ajax/project/remove_all_users/', ajax.remove_all_users, name="ajax_remove_all_users"),
                  # create file
                  path('ajax/project/create_file', ajax.create_file, name="create_file"),
                  # Create folder
                  path('ajax/project/create_folder', ajax.create_folder, name="create_folder"),
                  # Remove project or file or folder and subFile
                  path('ajax/project/remove', ajax.remove, name="remove"),
                  # Get all users affected by the project and return them
                  path('ajax/list_user/<str:type>/<int:id_project>', ajax.list_user_project,
                       name="mangement_list_user_affected"),
                  # get Settings page
                  path('settings', settings.index, name="settings_index"),
                  # set Setting
                  path('settings/set', settings.set_setting, name="set_setting"),
                  path('database/<int:database_id>', database.index, name="database_index"),
                  path('database/events/', database.event, name="get_dict")

              ] + static(django_settings.STATIC_URL, document_root=django_settings.STATIC_ROOT)
