import logging
from pymongo import MongoClient

class DBHandler():
  def __init__(self,db_host,db_port):
    self.db_host = db_host
    self.db_port = db_port

  def dbconnect(self):
    # Return a database handle
    client = MongoClient(
