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
from django.test import TestCase

from IDArling.models import Settings, Projects, Files, Databases, User
from IDArling_Management.BackendAuthentification import BackendAuthentification


class TestHeritage(TestCase):

    def setUp(self) -> None:
        self.settings = Settings.objects.create()
        self.group = Projects.objects.create(name="group_test")
        self.project = Files.objects.create(name="project_test", group=self.group)
        self.databases = Databases.objects.create(name="database_test", project=self.project)
        BackendAuthentification.create_user(username='oscar', password='top_secret');
        self.oscar = User.objects.get(username='oscar')

    def test_upward_inheritance_read(self):
        """Check for correct propagation of the read permission upwards, when the upward_inheritance_read attribute of settings is true."""
        self.assertFalse(self.oscar.user_can_read(self.group))
        self.settings.upward_inheritance_read = True
        self.settings.save()
        self.oscar.set_permissions(self.databases, read=True)
        self.assertTrue(self.oscar.user_can_read(self.group))

    def test_upward_inheritance_write(self):
        """Check for correct propagation of the write permission upwards, when the upward_inheritance_write attribute of settings is true."""
        self.settings.upward_inheritance_write = True
        self.settings.save()
        self.assertFalse(self.oscar.user_can_write(self.databases))
        self.assertFalse(self.oscar.user_can_write(self.project))
        self.assertFalse(self.oscar.user_can_write(self.group))
        self.oscar.set_permissions(self.databases, write=True)
        self.assertTrue(self.oscar.user_can_write(self.databases))
        self.assertTrue(self.oscar.user_can_write(self.project))
        self.assertTrue(self.oscar.user_can_write(self.group))

    def test_upward_inheritance_delete(self):
        """Check for correct propagation of the delete permission upwards, when the upward_inheritance_delete attribute of settings is true."""
        self.settings.upward_inheritance_delete = True
        self.settings.save()
        self.assertFalse(self.oscar.user_can_delete(self.databases))
        self.assertFalse(self.oscar.user_can_delete(self.project))
        self.assertFalse(self.oscar.user_can_delete(self.group))
        self.oscar.set_permissions(self.databases, delete=True)
        self.assertTrue(self.oscar.user_can_delete(self.databases))
        self.assertTrue(self.oscar.user_can_delete(self.project))
        self.assertTrue(self.oscar.user_can_delete(self.group))

    def test_descending_inheritance_read(self):
        """Check for correct propagation of the read permission descending, when the descending_inheritance_read attribute of settings is true."""
        self.assertFalse(self.oscar.user_can_read(self.group))
        self.assertFalse(self.oscar.user_can_read(self.databases))
        self.settings.descending_inheritance_read = True
        self.settings.save()
        self.oscar.set_permissions(self.group, read=True)
        self.assertTrue(self.oscar.user_can_read(self.group))
        self.assertTrue(self.oscar.user_can_read(self.databases))

    def test_descending_inheritance_write(self):
        """Check for correct propagation of the write permission descending, when the descending_inheritance_write attribute of settings is true."""
        self.assertFalse(self.oscar.user_can_write(self.group))
        self.assertFalse(self.oscar.user_can_write(self.databases))
        self.settings.descending_inheritance_write = True
        self.settings.save()
        self.oscar.set_permissions(self.group, write=True)
        self.assertTrue(self.oscar.user_can_write(self.group))
        self.assertTrue(self.oscar.user_can_write(self.databases))

    def test_descending_inheritance_delete(self):
        """Check for correct propagation of the delete permission descending, when the descending_inheritance_delete attribute of settings is true."""
        self.assertFalse(self.oscar.user_can_delete(self.group))
        self.assertFalse(self.oscar.user_can_delete(self.project))
        self.assertFalse(self.oscar.user_can_delete(self.databases))
        self.settings.descending_inheritance_delete = True
        self.settings.save()
        self.oscar.set_permissions(self.group, delete=True)
        self.assertTrue(self.oscar.user_can_delete(self.group))
        self.assertTrue(self.oscar.user_can_delete(self.project))
        self.assertTrue(self.oscar.user_can_delete(self.databases))
