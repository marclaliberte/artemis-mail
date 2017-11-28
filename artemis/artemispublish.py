#!/usr/bin/env python


import logging
import datetime
import subprocess
import threading
import os
import sys
import json
import cPickle
import copy


import server
import hpfeeds.hpfeeds as hpfeeds

logging.getLogger("analyzer")

class HPFHandler(object):
  def __init__(self,attachpath,inlinepath,hpf_host,hpf_port,hpf_ident,hpf_secret,filehandler):
    self.attachpath = attachpath
    self.inlinepath = inlinepath
    self.hpf_host = hpf_host
    self.hpf_port = hpf_port
    self.hpf_ident = hpf_ident
    self.hpf_secret = hpf_secret
    self.filehandler = filehandler

  def push(self):
    logging.info("[+]Inside artemispublish Module")
    
    for record in server.QueueReceiver.deep_records:
      logging.info("Records are %d" % len(server.QueueReceiver.deep_records))

        # Checking for attachments and dumping into directory, if any.
      if len(record['attachmentFile']) > 0:
        i = 0
        while i < len(record['attachmentFile']):
          logging.debug("Attachment found, saving locally")
          fileName = str(record['s_id']) + "-a-" + str(record['attachmentFileName'][i])
          path = self.attachpath + fileName
          attachFile = open(path, 'wb')
          attachFile.write(record['attachmentFile'][i])
          attachFile.close()
          #record['attachmentFile'][i] = path

        # Checking for inline attachment files
      if len(record['inlineFile']) > 0:
        i = 0
        while i < len(record['inlineFile']):
          logging.debug("Inline file found, saving locally")
          fileName = str(record['s_id']) + "-i-" + str(record['inlineFileName'][i])
          path = self.inlinepath + fileName
          attachFile = open(path, 'wb')
          attachFile.write(record['inlineFile'][i])
          attachFile.close()

  
  def sendfeed(self):
    sendparsed = True
    channel = {"parsed": "artemis.parsed", "ip_url": "artemis.urls"}
    
    try:
      hpc = hpfeeds.new(self.hpf_host,self.hpf_port,self.hpf_ident,self.hpf_secret)
    except Exception, e:
      logging.critical("Cannot connect. %s" % e)
        
    for record in server.QueueReceiver.deep_records:
      if sendparsed is True:
        try:
          data = cPickle.dumps(record)
          hpc.publish(channel["parsed"], data)
          logging.info("Record sent.")
        except Exception, e:
          logging.critical("[-] Error (artemispublish parsed) in publishing to hpfeeds. %s" % e)   
    
      if len(record['links']) > 0:
        for link in record['links']:
          try:
            data = {"id": record['s_id'], "url": link}
            data = json.dumps(data)
            hpc.publish(channel["ip_url"], data)
          except Exception, e:
            logging.critical("[-] Error (artemispublish link) in publishing to hpfeeds. %s" % e)
                
      ip_list = record['sourceIP'].split(',')            
      for ip in ip_list:
        try:
          data = {"id": record['s_id'], "source_ip": ip}
          data = json.dumps(data)
          hpc.publish(channel["ip_url"], data)
        except Exception, e:
          logging.critical("[-] Error (artemispublish ip) in publishing to hpfeeds. %s" % e)
                
    logging.info("[+]artemispublish Module: Calling sendfiles module.")
    file_thread = threading.Thread(name='Artemis File Handler', target=self.filehandler.main())
    file_thread.start()
        
  def cleanup(self):
    server.QueueReceiver.deep_records = copy.deepcopy(server.QueueReceiver.records)
    del server.QueueReceiver.records[:]
    server.QueueReceiver.totalRelay = 0
    logging.info("[+]artemispublish Module: List and global list counter resetted.")
    
  def getspammeremails(self):
    for record in server.QueueReceiver.deep_records:
      try:
        if record['counter'] < 30:
          logging.info("type: %s, record to values: %s" % (type(record['to']), record['to']))
          server.whitelist_ids[record['s_id']] = record['to'].split(",")

                
          for key, value in server.whitelist_ids.items():
            logging.info("New record - key: %s, value: %s" % (key, value))
                                
      except Exception, e:
        logging.critical("[-] Error (artemispublish getspammeremails) - some issue adding to whitelist %s" % e)
