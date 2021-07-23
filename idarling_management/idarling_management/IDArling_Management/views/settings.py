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

from django.contrib.admin.views.decorators import user_passes_test
from django.forms import model_to_dict
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST

from IDArling.models import Settings
from IDArling_Management.utils import Utils_Data


@user_passes_test(Utils_Data.UtilsData.admin_check)
@require_GET
def index(request):
    settings = Settings.objects.first()
    return render(request, 'settings.html', model_to_dict(settings))


@user_passes_test(Utils_Data.UtilsData.admin_check)
@require_POST
def set_setting(request):
    name = request.POST.get('id')
    value = request.POST.get('value')
    settings = Settings.objects.first()
    if name != "id":
        settings.__dict__[name] = value
        settings.save()
    return HttpResponse(json.dumps("ok"),
                        content_type="application/json")
