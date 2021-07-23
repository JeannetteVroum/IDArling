import select
import threading

import psycopg2.extensions
from django.db import connection


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Channel(object, metaclass=Singleton):

    def __init__(self):
        self.crs = connection.cursor()
        self.observers_notepad = list()
        self.observers_comment = list()
        self.pg_con = connection.connection
        self.pg_con.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        task = threading.Thread(target=self.listen)
        task.start()

    def listen(self):
        a = self.crs.execute("LISTEN database;")
        print("Waiting notification on notepad channel")
        while 1:
            if select.select([self.pg_con], [], [], 5) == ([], [], []):
                pass  # timeout
            else:
                self.pg_con.poll()
                while self.pg_con.notifies:
                    notifiy = self.pg_con.notifies.pop()
                    if not "webapp" in notifiy.payload:
                        for obs in self.observers_notepad:
                            obs.wake_up()

    def notify(self, id_database):
        crs = connection.cursor()
        query = '''notify database , %s;'''
        payload = id_database + "_webapp"
        crs.execute(query, [payload])
        crs.close()
