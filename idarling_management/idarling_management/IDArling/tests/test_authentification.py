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
from django.test import TestCase, Client

from IDArling_Management.BackendAuthentification import BackendAuthentification


class TestAuthentification(TestCase):

    def setUp(self) -> None:
        BackendAuthentification.create_user(username='pierre', password='top_secret')

    def test_username_password_authentification_fail(self):
        c = Client()
        response = c.post('/login', {"username": "pierre", "password": "wrong_password",
                                     "type_authentification": "username"})
        self.assertEqual(response.status_code, 400)

    def test_username_password_authentification_success(self):
        c = Client()
        response = c.post('/login', {"username": "pierre", "password": "top_secret",
                                     "type_authentification": "username"})
        self.assertRedirects(response=response, expected_url="/accounts/", status_code=302, target_status_code=200,
                             msg_prefix='', fetch_redirect_response=True)
