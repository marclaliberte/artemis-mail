#! /usr/bin/python
import datetime
import logging
import os

from artemisscheduler import ArtemisScheduler
from artemispublish import HPFHandler
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
               hpfeedspam,
               blackhole_domains):

    #Check if directories are present, create if not
    self._create_dirs([undeliverable_path,rawspampath,hpfeedspam,attachpath,inlinepath,hpfeedattach])

    #Handler for new spam messages
    self.newrecordhandler = NewRecordHandler(rawspampath,queuepath,globalcounter,relay,blackhole_domains)
    #Handler for old repeat spam messages
    self.oldrecordhandler = OldRecordHandler(globalcounter,queuepath,relay,blackhole_domains)
    #Handler for deciding if a message is new spam or repeat spam
    self.concluder = Conclude(self.newrecordhandler,self.oldrecordhandler)
    #Handler for parsing mail messages
    self.mailparser = ArtemisMailParser(queuepath,undeliverable_path,self.concluder)
    #HPFeeds file handler
    self.filehandler = FileHandler(hpf_host,hpf_port,hpf_ident,hpf_secret,rawspampath,attachpath,hpfeedspam,hpfeedattach)
    #Hpfeeds main communication handler
    self.hpfhandler = HPFHandler(attachpath,inlinepath,hpf_host,hpf_port,hpf_ident,hpf_secret,self.filehandler)
    #Scheduler for publishing to hpfeeds and cleaning up records
    self.scheduler = ArtemisScheduler(self.hpfhandler,sched_timer)
    #Handler for grabbing spam messages out of queue
    self.receiver = QueueReceiver(queuepath)

  def start(self):
    self.receiver.start(self.scheduler,self.mailparser)


  def _create_dirs(self,pathList):
    for path in pathList:
      if not os.path.exists(path):
        os.makedirs(path,0755)
