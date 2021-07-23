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

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from IDArling.models import Databases, Events
from IDArling_Management.utils.Utils_Data import UtilsData

logger = logging.getLogger(__name__)


@require_GET
@login_required
def index(request, database_id: int):
    # @todo check is can read
    database = Databases.objects.get(pk=database_id)
    can_write = request.user.can_write(database)
    events = Events.objects.all().filter(database__exact=database)
    if not can_write:
        can_write = "disabled"
    return render(request, 'databaseInformation.html', {
        'database_id': database_id, 'disabled': can_write, "events": events
    })


@require_GET
@login_required
def event(request):
    database_id = int(request.GET.get('database_id'))
    logger.info("Database_id = %s " % database_id)
    logger.info("type is " + str(type(database_id)))
    database = Databases.objects.get(pk=database_id)

    logger.info("database type " + str(type(database)))
    events = Events.objects.filter(database__exact=database).all()
    return_events = list()
    for event in events:
        retour = dict()
        print("user in event %s " % event.user)
        retour["user"] = event.user.username if event.user is not None else "Deleted"
        dict_of_dict = json.loads(event.dict)
        retour['dict'] = json.loads(event.dict)
        retour["event_type"] = dict_of_dict['event_type']
        retour['dict'] = retour["event_type"]
        retour['ea'] = dict_of_dict['ea']
        retour['options'] = dict_of_dict
        del dict_of_dict['token']
        del dict_of_dict['type']
        del dict_of_dict['ea']
        retour["tick"] = event.tick
        retour['details'] = dict_of_dict
        return_events.append(retour)
    return HttpResponse(json.dumps(return_events, default=UtilsData.default),
                        content_type="application/json")
