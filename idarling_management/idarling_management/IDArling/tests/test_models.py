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

from IDArling.models import User, Projects, Files, Databases


class TestModels(TestCase):

    def setUp(self) -> None:
        oscar_user = User.objects.create(username="oscar")
        self.oscar = User.objects.create(username="oscar", user=oscar_user)
        alice_user = User.objects.create(username="alice")
        self.alice = User.objects.create(username="alice", user=alice_user)

    def test_heritage_project_group(self) -> None:
        self.assertEqual(self.oscar.permissions_set.count(), 0)
        group = Projects.objects.create(name="groupTest")
        project = Files.objects.create(name="projectTest", group=group)
        self.assertFalse(group.user_can_read(self.oscar))
        self.assertFalse(project.user_can_read(self.oscar))
        self.assertFalse(group.user_can_write(self.oscar))
        self.assertFalse(project.user_can_write(self.oscar))
        project.set_permission(self.oscar, read=True)
        self.assertEqual(self.oscar.permissions_set.count(), 2)
        self.assertTrue(project.user_can_read(self.oscar))
        self.assertTrue(group.user_can_read(self.oscar))
        project.set_permission(self.oscar, write=True)
        self.assertTrue(group.user_can_write(self.oscar))
        self.assertTrue(project.user_can_write(self.oscar))
        project.set_permission(self.oscar, read=False, write=False)
        self.assertTrue(group.user_can_write(self.oscar))
        self.assertFalse(project.user_can_write(self.oscar))

    def test_heritage_database_projet(self):
        self.assertEqual(self.oscar.permissions_set.count(), 0)
        group = Projects.objects.create(name="groupTest")
        project = Files.objects.create(name="projectTest", group=group)
        database = Databases.objects.create(name="databaseProject", project=project)
        self.assertFalse(group.user_can_read(self.oscar))
        self.assertFalse(project.user_can_read(self.oscar))
        self.assertFalse(database.user_can_read(self.oscar))
        database.set_permission(self.oscar, read=True)
        database.set_permission(self.oscar, write=True)
        self.assertTrue(group.user_can_write(self.oscar))
        self.assertTrue(group.user_can_read(self.oscar))
        self.assertTrue(project.user_can_read(self.oscar))
        self.assertTrue(project.user_can_read(self.oscar))
        self.assertTrue(database.user_can_read(self.oscar))
        self.assertTrue(database.user_can_read(self.oscar))

    def test_user_groupes_permission(self):
        reader_group = UserGroupe.objects.create(name="reader")
        reader_group.users.add(self.oscar)
        reader_group.users.add(self.alice)
        group = Projects.objects.create(name="groupTest")
        self.assertFalse(group.user_can_read(self.oscar))
        group.set_permission(reader_group, read=True)
        self.assertTrue(group.user_can_read(self.oscar))
        group.set_permission(reader_group, read=False)
        self.assertFalse(group.user_can_read(self.oscar))

    def test_view_permissions(self):
        group = Projects.objects.create(name="groupTest")
        project = Files.objects.create(name="projectTest", group=group)
        database = Databases.objects.create(name="databaseTest", project=project)

        group_two = Projects.objects.create(name="GroupTest2")
        project_two = Files.objects.create(name="projectTest2", group=group)
        database_two = Databases.objects.create(name="databaseTest2", project=project)
        group.set_permission(self.oscar, read=True, write=False)
        self.oscar.tree_of_permissions()
        user_group = UserGroupe(name="group_of_users")
        user_group.save()
        user_group.users.add(self.oscar)
        user_group.users.add(self.alice)

        group_two.set_permission(user_group, read=True, write=True)
        self.assertTrue(group.user_can_read(self.oscar))
        self.assertFalse(group.user_can_write(self.oscar))
        self.oscar.tree_of_permissions()
