# chat/consumers.py
import json
import logging

from channels.generic.websocket import WebsocketConsumer

from IDArling.models import Databases, User
from .Channel import Channel
from .utils.Utils_Data import UtilsData

a = Channel()


class NotepadConsumer(WebsocketConsumer):
    logger = logging.getLogger(__name__)

    def connect(self):
        self.logger.info("test")
        user = self.scope["user"]
        self.database_id = self.scope['url_route']['kwargs']['database_id']
        self.logger.info("User % access to notepad's database %s " % (user, self.database_id))
        db = UtilsData.get_object_by_type_and_id("database", self.database_id)
        user = User.objects.filter(username=user).first()
        self.can_write = user.can_write(db)
        self.can_read = user.can_read(db)
        # retrieve notepad content in database
        self.accept()
        notepad_content = Databases.objects.get(pk=self.database_id).notepad
        a.observers_notepad.append(self)
        if self.can_write:
            self.send(text_data=json.dumps({
                'message': notepad_content
            }))
        elif self.can_read:
            self.send(text_data=json.dumps({
                'message': notepad_content,
                'error': 'don"t have the permission to write '
            }))
        else:
            self.logger.warning("User %s try to access notepad's database %s without permission"
                                % (user, self.database_id))
            self.close()

    def disconnect(self, close_code):
        a.observers_notepad.remove(self)

    def wake_up(self):
        notepad_content = Databases.objects.get(pk=self.database_id).notepad
        self.send(text_data=json.dumps({
            'message': notepad_content
        }))

    def forward(self, notepad_content):
        for client in a.observers_notepad:
            if client.database_id == self.database_id and client is not self:
                client.send(text_data=json.dumps({
                    'message': notepad_content
                }))

    def receive(self, text_data):
        # check if user can write to the database
        user = self.scope["user"]
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        # change content notepad if user can write
        if self.can_write:
            self.logger.info("User %s change notepad's content for database %s "
                             % (user, self.database_id))
            db = Databases.objects.get(pk=self.database_id)
            db.notepad = message
            db.save()
            # send update to Notify postgresql
            a.notify(self.database_id)
            # send new content to all WebSocket
            self.forward(message)
        """
        self.send(text_data=json.dumps({
            'message': message
        }))
        """


class CommentConsumer(WebsocketConsumer):
    logger = logging.getLogger(__name__)

    def connect(self):
        self.logger.info("test")
        user = self.scope["user"]
        self.user = User.objects.filter(username=user).first()
        # retrieve notepad content in database
        self.accept()
        a.observers_comment.append(self)

    def receive(self, text_data):
        # check if user can write to the database
        user = self.scope["user"]
        print("text is " + text_data)
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        database_id = text_data_json['id']
        db = UtilsData.get_object_by_type_and_id("database", database_id)
        can_write = self.user.can_write(db)
        # change content notepad if user can write
        if can_write:
            self.logger.info("User %s change comment's content for database %s "
                             % (user, database_id))
            db = Databases.objects.get(pk=database_id)
            db.comments = message
            db.save()
            # send update to Notify postgresql
            a.notify(database_id)
            # send new content to all WebSocket
            self.forward(message, db)

    def disconnect(self, close_code):
        a.observers_comment.remove(self)

    def wake_up(self):
        comment_content = Databases.objects.get(pk=self.database_id).comments
        self.send(text_data=json.dumps({
            'message': comment_content
        }))

    def forward(self, comment_content, db):
        for client in a.observers_comment:
            if client is not self and client.user.can_read(db):
                client.send(text_data=json.dumps({
                    'message': comment_content,
                    'id': db.id
                }))
