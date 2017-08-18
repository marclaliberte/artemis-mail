import logging
import datetime

import server

class OldRecordHandler(object):
  def __init__(self,globalcounter,queuepath,relay,blackhole_domains):
    self.globalcounter = globalcounter
    self.queuepath = queuepath
    self.relay = relay
    self.blackhole_domains = blackhole_domains

  def main(self,mailFields, matchedHash, key, msgMailRequest):
    logging.info("[+]Inside artemisprocessold Module.")

    records = server.QueueReceiver.records

    for record in records:
      if record['s_id'] == matchedHash:

        if mailFields['attachmentFileMd5']:
          i = 0
          while i < len(mailFields['attachmentFileMd5']):
            if mailFields['attachmentFileMd5'][i] not in record['attachmentFileMd5']:
              record['attachmentFile'].append(mailFields['attachmentFile'][i])
              record['attachmentFileMd5'].append(mailFields['attachmentFileMd5'][i])
              record['attachmentFileName'].append(mailFields['attachmentFileName'][i])
            i += 1

        if mailFields['links']:
          for newLink in mailFields['links']:
            if newLink not in record['links']:
              record['links'].append(newLink)

        if record['inlineFileMd5'] != mailFields['inlineFileMd5']:
          i = 0
          while i < len(mailFields['inlineFileMd5']):
            if mailFields['inlineFileMd5'][i] not in record['inlineFileMd5']:
              record['inlineFile'].append(mailFields['inlineFile'][i])
              record['inlineFileMd5'].append(mailFields['inlineFileMd5'][i])
              record['inlineFileName'].append(mailFields['inlineFileName'][i])
            i += 1

        ipList = record['sourceIP'].split(", ")
        if mailFields['sourceIP'] not in ipList:
          record['sourceIP'] = record['sourceIP'] + ", " + mailFields['sourceIP']

        sensorIDs = record['sensorID'].split(", ")
        if mailFields['sensorID'] not in sensorIDs:
          record['sensorID'] =  mailFields['sensorID'] + ", " + record['sensorID']
                
        recipients = record['to'].split(",")
        if mailFields['to'] not in recipients:
          record['to'] = record['to'] + "," + mailFields['to']
                
        user_list = record['user'].split(", ")
        if mailFields['user'] not in user_list:
          record['user'] = record['user'] + ", " + mailFields['user']

        record['counter'] += 1
        logging.info("value of record counter has reached: %s" % record['counter'])
            
        if self.relay is True and mailFields['to'].split("@")[1] not in self.blackhole_domains:
                
          if (int(server.QueueReceiver.totalRelay) > self.globalcounter):
            logging.info("[+]artemisprocessold Module: Limit reached. No relay.")
                                  
          elif next((i for i, sublist in enumerate([myval for myval in server.whitelist_ids.values()]) if mailFields['to'] in sublist), -1) > -1:
            logging.info("[+]artemisprocessold Module: Recipient found in white list - relaying")
                    
            # Following 3 lines does the relaying
            processMessage = server.QueueReceiver(self.queuepath)
            processMessage.process_message(msgMailRequest)
                    
            record['relayed'] += 1
            server.QueueReceiver.totalRelay += 1
          else:
            if record['counter'] <= 11:
              if record['counter'] == 11:
                logging.info("counter is = 11")
                logging.info("automated scanning has started - Not relaying anymore")
                server.whitelist_ids.pop(mailFields['s_id'], None)
                            
                logging.info("poping automated key")
                for key, value in server.whitelist_ids.items():
                  logging.info("key: %s, value: %s" % (key, value))
                            
              else:
                logging.info("[+]artemisprocessold Module: Adding recipient to whitelist and relaying")
                                    
                if mailFields['s_id'] in server.whitelist_ids:
                  logging.info("spam-id in whitlist - extending")
                  server.whitelist_ids[mailFields['s_id']].append(mailFields['to'])
                else:
                  logging.info("spam-id not in whitelist - adding")
                  server.whitelist_ids[mailFields['s_id']] = mailFields['to'].split()
                            
                logging.info("\n\nprocessold after adding new recipient\n\n")
                for key, value in server.whitelist_ids.items():
                  logging.info("key: %s, value: %s" % (key, value))
                            
                # Following 3 lines does the relaying
                processMessage = server.QueueReceiver(self.queuepath)
                processMessage.process_message(msgMailRequest)

                record['relayed'] += 1
                server.QueueReceiver.totalRelay += 1
        
