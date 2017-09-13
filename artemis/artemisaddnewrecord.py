"""This module inserts spam's details into a temporary list. This gets called 
everytime our analyzer come across a new/distinct spam. First, all the parser 
fields are stored as a dictionary and then, that dictionary is appended into
the list. 
"""

import logging
import server
import shutil
import datetime

import server

logging.getLogger("analyzer")

class NewRecordHandler(object):
  def __init__(self,rawspampath,queuepath,globalcounter,relay,blackhole_domains):
    self.rawspampath = rawspampath
    self.queuepath = queuepath
    self.globalcounter = globalcounter
    self.relay = relay
    self.blackhole_domains = blackhole_domains

  def main(self,mailFields, key, msgMailRequest):
    """Main function. 
    Stores the parsed fields as dictionary and then appends it to our
    temporary list.
    """
    logging.info("Inside artemisaddnewrecord Module.")

    records = server.QueueReceiver.records
    source = self.queuepath + "/new/" + key
    filename = mailFields['s_id'] + "-" + key
    destination = self.rawspampath + filename
    shutil.copy2(source, destination) # shutil.copy2() copies the meta-data too

    newRecord = { 'headers':mailFields['headers'], 
                'to':mailFields['to'], 
                'from':mailFields['from'], 
                'subject':mailFields['subject'], 
                'date':mailFields['date'], 
                'firstSeen':mailFields['firstSeen'], 
                'lastSeen':mailFields['lastSeen'], 
                'firstRelayed':mailFields['firstRelayed'], 
                'lastRelayed':mailFields['lastRelayed'], 
                'sourceIP':mailFields['sourceIP'], 
                'sensorID':mailFields['sensorID'], 
                'text':mailFields['text'], 
                'html':mailFields['html'], 
                'inlineFileName':mailFields['inlineFileName'], 
                'inlineFile':mailFields['inlineFile'], 
                'inlineFileMd5':mailFields['inlineFileMd5'], 
                'attachmentFileName': mailFields['attachmentFileName'],
                'attachmentFile':mailFields['attachmentFile'], 
                'attachmentFileMd5':mailFields['attachmentFileMd5'], 
                'links':mailFields['links'], 
                'ssdeep':mailFields['ssdeep'], 
                's_id':mailFields['s_id'], 
                'len':mailFields['len'], 
                'user':mailFields['user'], 
                'counter':1, 
                'relayed':0 }

    if self.relay is True:
      if mailFields['to'].split("@")[1] in self.blackhole_domains:
          logging.info("Email in blackhole_domains, skipping relay")
      else:
        if (int(server.QueueReceiver.totalRelay) > self.globalcounter):
          logging.info("[+]artemisaddnewrecord Module: Limit reached. No relay.")
            
        elif next((i for i, sublist in enumerate([myval for myval in server.whitelist_ids.values()]) if mailFields['to'] in sublist), -1) > -1:
          logging.info("[+]artemisaddnewrecord Module: Recipient found in white list - relaying")
            
     	  # Following 3 lines does the relaying
  	  processMessage = server.QueueReceiver(self.queuepath)
	  processMessage.process_message(msgMailRequest)

          newRecord['relayed'] += 1
          server.QueueReceiver.totalRelay += 1
        else:
          logging.info("[+]artemisaddnewrecord Module: Adding recipient to whitelist and relaying")
                            
          server.whitelist_ids[mailFields['s_id']] = mailFields['to'].split()
       
          for key, value in server.whitelist_ids.items():
            logging.info("key: %s, value: %s" % (key, value))
            
          # Following 3 lines does the relaying
          processMessage = server.QueueReceiver(self.queuepath)
          processMessage.process_message(msgMailRequest)

          newRecord['relayed'] += 1
          server.QueueReceiver.totalRelay += 1
           
            
    records.insert(0, newRecord) #Inserting new record at the first position.
    del newRecord
