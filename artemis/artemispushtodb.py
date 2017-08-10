#!/usr/bin/env python


import logging
import datetime
import subprocess
import os
import sys
import json
import cPickle
import copy


import server
import hpfeeds.hpfeeds as hpfeeds
#import artemisdbconfig #import when mongo added

class DBHandler(object):
  def __init__(self,attachpath,inlinepath,hpf_host,hpf_port,hpf_ident,hpf_secret):
    self.attachpath = attachpath
    self.inlinepath = inlinepath
    self.hpf_host = hpf_host
    self.hpf_port = hpf_port
    self.hpf_ident = hpf_ident
    self.hpf_secret = hpf_secret

  def push(self):
    logging.info("[+]Inside artemispushtodb Module")
#    exeSql = artemisdbconfig.dbconnect() #Fix when mongo added
    
#    attachpath = server.artemisconf.get('analyzer', 'attachpath')
#    inlinepath = server.artemisconf.get('analyzer', 'inlinepath')    
    
    truncate = ['truncate attachments','truncate links', 'truncate sensors', 'truncate spam']
    for query in truncate:
      try:
        exeSql.execute(query)
      except Exception, e:
        logging.critical("[-] Error (artemispushtodb) truncate %s" % str(e))
            
    
    for record in server.QueueReceiver.deep_records:
      logging.info("Records are %d" % len(server.QueueReceiver.deep_records))

      values = str(record['s_id']), str(record['ssdeep']), str(record['to']), str(record['from']), str(record['text']), str(record['html']), str(record['subject']), str(record['headers']), str(record['sourceIP']), str(record['sensorID']), str(record['firstSeen']), str(record['relayed']), str(record['counter']), str(record['len']), str(record['firstRelayed']), str(record['user'])
      insertSpam = "INSERT INTO `spam`(`id`, `ssdeep`, `to`, `from`, `textMessage`, `htmlMessage`, `subject`, `headers`, `sourceIP`, `sensorID`, `firstSeen`, `relayCounter`, `totalCounter`, `length`, `relayTime`, `user`) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"

      try:
        exeSql.execute(insertSpam, values)
      except mdb.Error, e:
        logging.critical("[-] Error (artemispushtodb insert_spam) - %d: %s" % (e.args[0], e.args[1]))

        # Checking for attachments and dumping into directory, if any. Also storing information in database.
      if len(record['attachmentFile']) > 0:
        i = 0
        while i < len(record['attachmentFile']):
          fileName = str(record['s_id']) + "-a-" + str(record['attachmentFileName'][i])
          path = attachpath + fileName
          attachFile = open(path, 'wb')
          attachFile.write(record['attachmentFile'][i])
          attachFile.close()
          #record['attachmentFile'][i] = path
          values = str(record['s_id']), str(mdb.escape_string(record['attachmentFileName'][i])), 'attach', str(record['attachmentFileMd5'][i]), str(record['date']), str(mdb.escape_string(path))
          insertAttachment = "INSERT INTO `attachments`(`spam_id`, `file_name`, `attach_type`, `attachmentFileMd5`, `date`, `attachment_file_path`) VALUES (%s, %s, %s, %s, %s, %s)"
              
          try:
            exeSql.execute(insertAttachment, values)
            i += 1

          except mdb.Error, e:
            logging.critical("[-] Error (artemispushtodb insert_attachment) - %d: %s" % (e.args[0], e.args[1]))

        # Checking for inline attachment files
      if len(record['inlineFile']) > 0:
        i = 0
        while i < len(record['inlineFile']):
          fileName = str(record['s_id']) + "-i-" + str(record['inlineFileName'][i])
          path = inlinepath + fileName
          attachFile = open(path, 'wb')
          attachFile.write(record['inlineFile'][i])
          attachFile.close()
          values = str(record['s_id']), str(mdb.escape_string(record['inlineFileName'][i])), 'inline', str(record['inlineFileMd5'][i]), str(record['date']), str(mdb.escape_string(path))
          insertInline = "INSERT INTO `attachments`(`spam_id`, `file_name`, `attach_type`, `attachmentFileMd5`, `date`, `attachment_file_path`) VALUES (%s, %s, %s, %s, %s, %s)"

          try:
            exeSql.execute(insertInline, values)
            i += 1
          except mdb.Error, e:
            logging.critical("[-] Error (artemispushtodb insert_inline) - %d: %s" % (e.args[0], e.args[1]))

        # Checking for links in spams and storing them
      if len(record['links']) > 0:
        i = 0
        for link in record['links']:
          values =  str(record['s_id']), str(link), str(record['date'])
          insertLink = "INSERT INTO `links` (`spam_id`, `hyperlink`, `date`) VALUES (%s, %s, %s)"

          try:
            exeSql.execute(insertLink, values)
            i += 1
          except mdb.Error, e:
            logging.critical("[-] Error (artemispushtodb insert_link) - %d: %s" % (e.args[0], e.args[1]))


        # Extracting and saving name of the sensor
      values = str(record['s_id']), str(record['sensorID']), str(record['date'])
      insertSensor = "INSERT INTO `sensors` (`spam_id`, `sensorID`, `date`) VALUES (%s, %s, %s)"

      try:
        exeSql.execute(insertSensor, values)
      except mdb.Error, e:
        logging.critical("[-] Error (artemispushtodb insert_sensor - %d: %s" % (e.args[0], e.args[1]))
          
    subprocess.Popen(['python', os.path.dirname(os.path.realpath(__file__)) + '/artemismaindb.py'])
    logging.info("Shivamaindb called")
#    exeSql.close()
  
  def sendfeed(self):
    
#    host = server.artemisconf.get('hpfeeds', 'host')
#    port = server.artemisconf.getint('hpfeeds', 'port')
#    ident = server.artemisconf.get('hpfeeds', 'ident')
#    secret = server.artemisconf.get('hpfeeds', 'secret')
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
          logging.critical("[-] Error (artemispushtodb parsed) in publishing to hpfeeds. %s" % e)   
    
      if len(record['links']) > 0:
        for link in record['links']:
          try:
            data = {"id": record['s_id'], "url": link}
            data = json.dumps(data)
            hpc.publish(channel["ip_url"], data)
          except Exception, e:
            logging.critical("[-] Error (artemispushtodb link) in publishing to hpfeeds. %s" % e)
                
      ip_list = record['sourceIP'].split(',')            
      for ip in ip_list:
        try:
          data = {"id": record['s_id'], "source_ip": ip}
          data = json.dumps(data)
          hpc.publish(channel["ip_url"], data)
        except Exception, e:
          logging.critical("[-] Error (artemispushtodb ip) in publishing to hpfeeds. %s" % e)
                
    logging.info("[+]artemispushtodb Module: Calling sendfiles module.")
#    subprocess.Popen(['python', os.path.dirname(os.path.realpath(__file__)) + '/hpfeeds/sendfiles.py'])
#TODO: INTEGRATE INTO NON-BLOCKING HANDLER
        
  def cleanup(self):
    server.QueueReceiver.deep_records = copy.deepcopy(server.QueueReceiver.records)
    del server.QueueReceiver.records[:]
    server.QueueReceiver.totalRelay = 0
    logging.info("[+]artemispushtodb Module: List and global list counter resetted.")
    
  def getspammeremails(self):
    """
#FIX WHEN MONGO IS ADDED
    mainDb = artemisdbconfig.dbconnectmain()
    
    whitelist = "SELECT `recipients` from `whitelist`"
    
    try:
      mainDb.execute(whitelist)
      record = mainDb.fetchone()
      if ((record is None) or (record[0] is None)):
        server.whitelist_ids['spammers_email'] = []
                  
      else:
        server.whitelist_ids['spammers_email'] = (record[0].encode('utf-8')).split(",")[-100:]
        server.whitelist_ids['spammers_email'] = list(set(server.whitelist_ids['spammers_email']))
            
                
      logging.info("[+] Pushtodb Module: whitelist recipients:")
      for key, value in server.whitelist_ids.items():
        logging.info("key: %s, value: %s" % (key, value))
            
      mainDb.close()
        
    except mdb.Error, e:
      logging.critical("[-] Error (Module artemispushtodb.py) - some issue obtaining whitelist: %s" % e)
    """
                
    for record in server.QueueReceiver.deep_records:
      try:
        if record['counter'] < 30:
          logging.info("type: %s, record to values: %s" % (type(record['to']), record['to']))
          server.whitelist_ids[record['s_id']] = record['to'].split(",")

                
          for key, value in server.whitelist_ids.items():
            logging.info("New record - key: %s, value: %s" % (key, value))
                                
      except Exception, e:
        logging.critical("[-] Error (Module artemispushtodb.py) - some issue adding to whitelist %s" % e)
