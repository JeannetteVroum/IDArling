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
from django.test import TestCase, Client, RequestFactory

from IDArling.models import User
from IDArling_Management.BackendAuthentification import BackendAuthentification
from IDArling_Management.views import account
from IDArling_Management.views.account import synchronise_account


class TestRegister(TestCase):

    def setUp(self) -> None:
        self.user, _ = BackendAuthentification.create_user(username='pierre', password='top_secret')
        self.factory = RequestFactory()

    def test_register_new_account_username_password(self):
        """test mecanic admin for register a new account"""
        c = Client()
        c.post('/login', {"username": "pierre", "password": "top_secret",
                          "type_authentification": "username"})
        """send new user"""
        response = c.post("/management/user/create", {"username": "nouvelleUtilisateur",
                                                      "password": "password123456"})
        self.assertEqual(response.status_code, 200)

    def test_register_account_exist_already(self):
        """test the error message and the database if the account already exists"""
        c = Client()
        self.assertEqual(len(User.objects.all()), 1)
        c.post('/login', {"username": "pierre", "password": "top_secret",
                          "type_authentification": "username"})
        response = c.post("/management/user/create", {"username": "pierre",
                                                      "password": "password123456"})
        self.assertEqual(len(User.objects.all()), 1)
        self.assertEqual(response.context["error"], "user exist")

    def test_synchronise_account(self):
        """test synchronisation between ldap account and normal account"""
        # Create fake ldap account
        ldap_user = User.objects.create(username="Ldap")
        user = User.objects.create(username="Ldap", authentificationByPassword=False, ldap_user=True, user=ldap_user)
        self.assertFalse(user.authentificationByPassword)
        self.assertTrue(user.ldap_user)
        request = self.factory.post("/accounts/synchronise_account",
                                    {
                                        "newPassword": "F6ntxsABcEwcjEw",
                                        "newPasswordVerify": "F6ntxsABcEwcjEw"
                                    })
        request.user = ldap_user
        response = synchronise_account(request)
        user = User.objects.get(pk=user.id)
        self.assertTrue(user.authentificationByPassword)
        self.assertTrue(user.ldap_user)

    def test_change_password(self):
        request = self.factory.post("/accounts/change_password",
                                    {
                                        "oldPassword": "top_secret",
                                        "newPassword": "toto1234",
                                        "newPasswordVerify": "toto1234"
                                    })
        request.user = self.user
        response = account.change_password(request)
        self.assertTrue(self.user.check_password("toto1234"))

    def test_change_password_error_wrong_password(self):
        """Tests the error message when the user tries to change his password by entering a wrong current password.
        Check that the password is not changed."""
        request = self.factory.post("/accounts/change_password",
                                    {
                                        "oldPassword": "wrong_password",
                                        "newPassword": "toto1234",
                                        "newPasswordVerify": "toto1234"
                                    })
        request.user = self.user
        response = account.change_password(request)
        self.assertTrue(b"Wrong password" in response.content)
        self.assertFalse(self.user.check_password("toto1234"))

    def test_change_password_not_identical_password(self):
        """Tests the error message when the user tries to change his password by entering two non-identical passwords.
        Check that the password is not changed."""
        request = self.factory.post("/accounts/change_password",
                                    {
                                        "oldPassword": "wrong_password",
                                        "newPassword": "toto123456",
                                        "newPasswordVerify": "toto1234"
                                    })
        request.user = self.user
        print("return : ", str(account.change_password(request)))
        response = account.change_password(request)
        self.assertTrue(b"Passwords are not identical" in response.content)
        self.assertFalse(self.user.check_password("toto1234"))

    def test_register_new_account_with_username_exist_already(self):
        """Checks that it is not possible to register a user with a username already in use"""
        self.assertEqual(1, len(User.objects.filter(username='pierre')))
        self.assertEqual(1, len(User.objects.filter(username='pierre')))
        BackendAuthentification.create_user(username='pierre', password='top_secret')
        self.assertEqual(1, len(User.objects.filter(username='pierre')))
        self.assertEqual(1, len(User.objects.filter(username='pierre')))
