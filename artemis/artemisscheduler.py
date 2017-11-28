#! /usr/bin/python
"""
Schedules a job to reset individual counters of relayed mail to 0.
Also sends records to hpfeeds.
This allows the spam pot to relay messages for new spammers. 
"""
import datetime
import logging

from apscheduler.scheduler import Scheduler

import server

logging.getLogger("analyzer")

class ArtemisScheduler(object):
  def __init__(self,hpfhandler,timer=60):
    self.duration = timer
    self.hpfhandler = hpfhandler

  def resetcounter(self):
    self.hpfhandler.cleanup()
    self.hpfhandler.getspammeremails()

    logging.info("[+]artemisscheduler.py: Pushing files to local storage")
    self.hpfhandler.push()
    logging.info("[+]artemisscheduler.py: Sending data to hpfeeds")
    self.hpfhandler.sendfeed()

  def schedule(self):
    sched = Scheduler()
    sched.add_interval_job(self.resetcounter, minutes=self.duration)
    sched.start()
    logging.info("Artemis scheduler, which resets global counter and sends data on hpfeeds, started at %s, executes every %d minutes " % (datetime.datetime.now(), self.duration))
