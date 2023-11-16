# database.py


import os.path
import sqlite3
from constants import *


class Database:
    def __init__(self):
        self.db_file = DB_FILE
        self.clients = []

    def connect(self):
        """ Connects to the database """
        conn = sqlite3.connect(self.db_file)
        conn.text_factory = bytes
        return conn

    @property
    def locate_database(self):
        """ This method creates the required tables in the DB.
        Ideally this should run one time when the server starts running. """
        if os.path.exists(self.db_file):
            print(f"Found existing Database at {self.db_file}.")
            return True

        else:
            print(f"Database was not found at {self.db_file}, creating a new one..")
            return self.create_databadse()

    def create_databadse(self):
        conn = self.connect()
        try:
            conn.executescript("""
              CREATE TABLE clients (ID CHAR(16) NOT NULL PRIMARY KEY,
              Name CHAR(255) NOT NULL,
              PublicKey CHAR(160),
              LastSeen DATE,
              AESKey CHAR(128)
              );""")

            conn.executescript("""
              CREATE TABLE files (
                  ClientID CHAR(16) NOT NULL,               
                  FileName CHAR(255),
                  PathName CHAR(255),
                  Verified INT,
                  PRIMARY KEY (ClientID, FileName),
                  FOREIGN KEY (ClientID) REFERENCES clients(ID)
              );""")
            print(f"New database was created at {self.db_file} successfully!")

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f'Database execution failed: {e}')
            return False

    def fetch_client_info(self):
        """ Load client data from the database. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients")
        self.clients = cur.fetchall()  # Storing client data in self.clients
        conn.close()

    def get_clients(self):
        """ Returns the list of clients. """
        return self.clients

    def is_known_user(self, user):
        """ Returns true if a given username exists in the DB. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients WHERE Name = ?", [user])
        info = cur.fetchall()
        conn.close()
        if info:
            return True
        return False

    def get_user_info_from_db(self, username):
        """ gets user information from the database based on the username. """
        byte_username = username.encode('utf-8')
        self.fetch_client_info()
        for client in self.clients:
            if byte_username in client[1]:
                user_info = {"UUID": client[0],
                             "PublicKey": client[2],
                "AESKey": client[4]}
                return user_info

        else:
            # If the user does not exist, return None
            return None

    def is_known_UUID(self, uuid):
        """ Returns true if a given UUID exists in the DB. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients WHERE ID = ?", [uuid])
        info = cur.fetchall()
        conn.close()
        if info:
            return True
        return False

    def register_client(self, id, name):
        """ Registers client into the clients table
        Assumes that the client is not there """
        return self.run_cmd(
            "INSERT INTO clients (ID, Name) VALUES (?, ?)", [id, name], True)

    def run_cmd(self, command, args=[], isCommit=False):
        """ Executes a command with the arguments provided """
        conn = self.connect()
        res = False
        try:
            cur = conn.cursor()
            cur.execute(command, args)
            if isCommit:
                conn.commit()
            else:
                res = cur.fetchall()
        except Exception as e:
            print(f'Warning: {e}')
        conn.close()
        return res

    def register_file(self, client_id, filename, pathname, verified):
        """ Registers file into the files table. Assumes that client_id refers to an existing client."""
        return self.run_cmd("INSERT INTO files (ClientID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)", [client_id, filename, pathname, verified], True)

    def set_last_seen(self, id, time):
        """ Given an ID, sets the LastSeen field to the received time. """
        return self.run_cmd("UPDATE clients SET LastSeen = ? WHERE ID = ?", [time, id], True)

    def set_AES_Key(self, id, key):
        """ Given an ID, sets the AES Key field to the received key. """
        return self.run_cmd("UPDATE clients SET AESKey = ? WHERE ID = ?", [key, id], True)

    def set_pubkey(self, id, key):
        """ sets the Public Key field to the received key. """
        return self.run_cmd("UPDATE clients SET PublicKey = ? WHERE ID = ?", [key, id], True)