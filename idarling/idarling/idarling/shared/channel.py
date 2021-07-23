import configparser
import select
import threading

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Channel(object, metaclass=Singleton):

    def __init__(self, server, logger):
        config = configparser.ConfigParser()
        cwd, _ = os.path.split(os.path.abspath(__file__))
        path = os.path.join(cwd, "..", "..", "setting_server.ini")
        config.read(path)
        self.server = server
        self.stop = False

        host =os.environ.get("SQL_HOST", config["Database"]["IP"])
        user = os.environ.get("SQL_USER",  config["Database"]["user"])
        password = os.environ.get("SQL_PASSWORD", config["Database"]["password"])
        database_name = os.environ.get("SQL_DATABASE",  config["Database"]["name"] )
        self.address = f"postgresql://{user}:{password}@{host}/{database_name}"
        self.logger = logger
        self.engine = create_engine(self.address)
        session_factory = sessionmaker(bind=self.engine)
        self.Session = scoped_session(session_factory)
        self.session = self.Session()
        self.task = threading.Thread(target=self.read_modification)
        self.task.start()
        self.logger.debug("Channel Started")

    def send_modification_notepad(self, id_database: int):
        self.logger.debug("Send modification notepad database %d" % id_database)
        self.session.execute(text("notify database").execution_options(autocommit=True))
        self.session.commit()
        # self.session.execute(text("notify database , '%d'" % id_database).execution_options(autocommit=True))

    def terminate_listen(self):
        """
        Stop listen thread
        """
        self.stop = True
        self.task.join()
        self.logger.trace("Stop read channel Thread")

    def read_modification(self):
        try:
            engine = create_engine(self.address)
            self.logger.debug("engine listen")
            conn = engine.connect()
            conn.execute(text("LISTEN database;").execution_options(autocommit=True))
            while 1 and not self.stop:
                if select.select([conn.connection], [], [], 5) == ([], [], []):
                    self.logger.debug("read modification on channel")
                else:
                    conn.connection.poll()
                    while conn.connection.notifies:
                        notify = conn.connection.notifies.pop()
                        if "webapp" in notify.payload:
                            self.server.send_web_application_changes(notify.payload)
        except Exception as e:
            self.logger.warning("Exception channel : %s " % e)
