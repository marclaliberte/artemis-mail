#! /usr/bin/python
"""
Schedules a job to reset individual counters of relayed mails to 0. 
This would make sure each spammer finds spamPot relaying everyday.
"""
import datetime
import logging

from apscheduler.scheduler import Scheduler

import server


class ArtemisScheduler(object):
  def __init__(self,dbhandler,timer=60,localdb=False,hpfeeds=True):
    self.duration = timer
    self.dbhandler = dbhandler
    self.localdb = localdb
    self.hpfeeds = hpfeeds

  def resetcounter(self):
    self.dbhandler.cleanup()
    self.dbhandler.getspammeremails()

    if self.localdb is True:
      logging.info("[+]artemisscheduler.py: Pushing data to local db")
      self.dbhandler.push()

    if self.hpfeeds is True:
      logging.info("[+]artemisscheduler.py: Sending data to hpfeeds")
      self.dbhandler.sendfeed()

  def schedule(self):
    sched = Scheduler()
    sched.add_interval_job(self.resetcounter, minutes=self.duration)
    sched.start()
    logging.info("Artemis scheduler, which dumps data into maindb, resets global counter and sends data on hpfeeds, started at %s and would execute every %d minutes " % (datetime.datetime.now(), self.duration))
