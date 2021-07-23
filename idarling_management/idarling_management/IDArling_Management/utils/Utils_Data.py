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
import datetime

from IDArling.models import Projects, Databases, Files, Folders


class UtilsData:

    @staticmethod
    def get_object_by_type_and_id(type: str, id: int):
        if type == 'project':
            return Projects.objects.get(pk=id)
        elif type == 'file':
            return Files.objects.get(pk=id)
        elif type == 'folder':
            print("not her")
            return Folders.objects.get(pk=id)
        elif type == 'database':
            return Databases.objects.get(pk=id)
        return None

    @staticmethod
    def default(o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()

    @staticmethod
    def admin_check(user):
        if user.is_superuser:
            return True
        return False

    @staticmethod
    def searchDc(email: str):
        username, secondpart = email.rsplit('@', 1)
        search_base = ""
        splittedDC = secondpart.split('.')
        for dc in splittedDC:
            search_base += "DC=" + dc + ","
        search_base = search_base[:-1]
        return username, search_base
