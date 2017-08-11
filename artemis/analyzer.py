#! /usr/bin/python
"""
Schedules a job to reset individual counters of relayed mails to 0. 
This would make sure each spammer finds spamPot relaying everyday.
"""
import datetime
import logging
import os

from artemisscheduler import ArtemisScheduler
from artemispushtodb import DBHandler
from artemismailparser import ArtemisMailParser
from artemisaddnewrecord import NewRecordHandler
from artemisprocessold import OldRecordHandler
from artemisconclude import Conclude
from artemisfilehandler import FileHandler
from server import QueueReceiver
import server

class Analyzer(object):
  def __init__(self,
               queuepath,
               undeliverable_path,
               rawspampath,
               sched_timer,
               attachpath,
               inlinepath,
               relay,
               indivcounter,
               globalcounter,
               hpf_host,
               hpf_port,
               hpf_ident,
               hpf_secret,
               hpfeedattach,
               hpfeedspam):

    self._create_dirs([undeliverable_path,rawspampath,hpfeedspam,attachpath,inlinepath,hpfeedattach])

    self.filehandler = FileHandler(hpf_host,hpf_port,hpf_ident,hpf_secret,rawspampath,attachpath,hpfeedspam,hpfeedattach)
    self.newrecordhandler = NewRecordHandler(rawspampath,queuepath,globalcounter,relay)
    self.oldrecordhandler = OldRecordHandler(globalcounter,queuepath,relay)
    self.concluder = Conclude(self.newrecordhandler,self.oldrecordhandler)
    self.mailparser = ArtemisMailParser(queuepath,undeliverable_path,self.concluder)
    self.dbhandler = DBHandler(attachpath,inlinepath,hpf_host,hpf_port,hpf_ident,hpf_secret,self.filehandler)
    self.scheduler = ArtemisScheduler(self.dbhandler,sched_timer)
    self.receiver = QueueReceiver(queuepath)

  def start(self):
    self.receiver.start(self.scheduler,self.mailparser)


  def _create_dirs(self,pathList):
    for path in pathList:
      if not os.path.exists(path):
        os.makedirs(path,0755)
