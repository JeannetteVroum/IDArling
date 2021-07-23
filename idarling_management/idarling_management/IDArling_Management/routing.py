# mysite/routing.py
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path

from IDArling_Management import consumers

application = ProtocolTypeRouter({
    # (http->django views is added by default)
    'websocket': AuthMiddlewareStack(
        URLRouter(
            [
                re_path(r'ws/notepad/(?P<database_id>\w+)/$', consumers.NotepadConsumer),
                re_path(r'ws/comment/$', consumers.CommentConsumer)
            ]
        )
    ),
})
