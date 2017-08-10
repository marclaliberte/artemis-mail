"""This module accepts spam file name as parameter and returns all parsed 
fields as items of a dictionary. In current state, it's accepting spam file
name as parameter, parsing all fields, saving in a dictionary and forwarding 
to artemisconclude module.
"""

from email.header import decode_header
import email.Message
import email.Parser
import logging
import os
import re
import datetime
import hashlib
import base64
import ConfigParser
import shutil
from email.utils import parseaddr

import ssdeep


class ArtemisMailParser(object):
  def __init__(self,queuepath,undeliverable_path,concluder):
    self.queuepath = queuepath
    self.undeliverable_path = undeliverable_path
    self.concluder = concluder
    # Global dictionary to store parsed fields of spam
    self.mailFields = {'headers':'', 'to':'', 'from':'', 'subject':'', 'date':'', 'firstSeen':'', 'lastSeen':'', 'firstRelayed':'', 'lastRelayed':'', 'sourceIP':'', 'sensorID':'', 'text':'', 'html':'', 'inlineFileName':[], 'inlineFile':[], 'inlineFileMd5':[], 'attachmentFileName':[], 'attachmentFile':[], 'attachmentFileMd5':[], 'links':[], 'ssdeep':'', 's_id':'', 'len':'', 'user':''}
    self.randomText = """@Deprecation
In Solr 1.3, many classes were moved around. Although classes compiled against 1.2 will run in 1.3, updating class references is recommended.
Specifically: many classes from org.apache.util moved to org.apache.common.util many classes from org.apache.solr.request moved to org.apache.solr.common.params org.apache.solr.request.StandardRequestHandler moved to org.apache.solr.handler.StandardRequestHandler and is a subclass of org.apache.solr.handler.SearchHandler
org.apache.solr.request.DisMaxRequestHandler moved to org.apache.solr.handler.DisMaxRequestHandler and deprecated in favor of adding 'defType=dismax' to StandardRequestHandler init params
Solr1.3 (last edited 2009-09-20 22:04:51 by localhost SHIVA."""

  def md5checksum(self,filepath):
    m = hashlib.md5()
    m.update(filepath)
    return m.hexdigest()
  
  def linkparser(self,input_body):
    """Returns a list containing URLs.
    """  
    
    URL_REGEX_PATTERN = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
    url_list = set([mgroups[0] for mgroups in URL_REGEX_PATTERN.findall(input_body)])
    url_list = list(set(url_list))
    
    return url_list

  def getfuzzyhash(self):
    """Returns fuzzy hash of spam.
    This function returns hash generated using the ssdeep library.
    Hash is generated using the combination of mail's body + subject.
    Msg length is being checked because SSDEEP has some issues with comparing hashes
    of small spams. If spam's body is very less or non existent, we add our randomText to body.
    There would be certain cases when there wouldn't be any html or text portion i.e. email body would be empty. Hence forth len = html/text + subject
    In artemismaindb.py if len < 10 then keeping comparision ratio higher
    """
    if self.mailFields['html']:
      if len(self.mailFields['html']) < 150:
        data = self.mailFields['html'] + " " + self.mailFields['subject'] + self.randomText
      else:
        data = self.mailFields['html'] + " " + self.mailFields['subject']
      self.mailFields['len'] = len(self.mailFields['html']) + len(self.mailFields['subject'])
    
    elif self.mailFields['text']:
      if len(self.mailFields['text']) < 150:
        data = self.mailFields['text'] + " " + self.mailFields['subject'] + self.randomText
      else:
        data = self.mailFields['text'] + " " + self.mailFields['subject']
      self.mailFields['len'] = len(self.mailFields['text']) + len(self.mailFields['subject'])
    else:
      # Test mails without body and limited chars in subject
      data = self.mailFields['subject'] + self.mailFields['from'] + self.randomText
      self.mailFields['len'] = len(self.mailFields['subject'])
    
    return ssdeep.hash(data)

  def fix_padding_for_attachments(payload):
    logging.critical("\t[+]Fixing Padding for Attachment if needed")
    payload = payload.rstrip()
    missing_padding = (4 - len(payload) % 4) % 4
    payload += '=' * missing_padding
    return base64.b64decode(payload)


  def movebadsample(self,key, msg):
    """Copies the troublesome spam to different folder and removes it from 
    queue.
    """
    
    logging.critical("\n**** [-] Error!!! ****")
    logging.critical("Copying spam file to distortedSamples directory before \
      moving it out of queue")
    shutil.copyfile(self.queuepath + 'new/' + key, self.undeliverable_path + key)
    
  def writepartsrecurse(self,msg):
    """This module recursively parses all fields of multipart spam mail
    and stores them in the dictionary.
    """
    while isinstance(msg.get_payload(), email.Message.Message):
      msg = msg.get_payload()
        
    if msg.is_multipart():
      for subMsg in msg.get_payload():
          self.writepartsrecurse(subMsg)

    else:
      content = msg.get_content_type()

      file_name, encoding = decode_header(msg.get_filename())[0]         #Function returns the encoding type if any

      file_name = file_name.replace("'", "")
      if encoding == None:
        fileName = file_name
      else:
        fileName = file_name.decode(encoding)
        fileName = fileName.encode('utf-8')

      if msg.get_content_type() == 'text/plain' and msg['Content-Disposition'] == None:  # value of content-dispostion is None in this case
        self.mailFields['text'] = msg.get_payload(decode=True)           # decode says - if in base64, decode the value
        
      elif msg.get_content_type() == 'text/html':                   # value of content-dispostion is None in this case
        self.mailFields['html'] = msg.get_payload(decode=True)
        
      elif msg['Content-Disposition'] != None and msg['Content-Disposition'].find('inline;') >= 0:   # if 'inline' file found
        logging.critical("Inside inline handling")
        payload = self.fix_padding_for_attachments(msg.get_payload())
        self.mailFields['attachmentFile'].append(payload)
        self.mailFields['attachmentFileName'].append(fileName)
        self.mailFields['attachmentFileMd5'].append(self.md5checksum(payload))

      elif msg['Content-Disposition'] != None and msg['Content-Disposition'].find('attachment;') >= 0:    # if attachment found
        logging.critical("Inside Attachment handling")
        payload = self.fix_padding_for_attachments(msg.get_payload())
        self.mailFields['attachmentFile'].append(payload)
        self.mailFields['attachmentFileName'].append(fileName)
        self.mailFields['attachmentFileMd5'].append(self.md5checksum(payload))

      # Sometimes "Content-Disposition" is missing, "attachment" is missing but "file name" is there with binary content
      elif msg.get_filename() != None:         
        payload = self.fix_padding_for_attachments(msg.get_payload())
        self.mailFields['attachmentFile'].append(payload)
        self.mailFields['attachmentFileName'].append(fileName)
        self.mailFields['attachmentFileMd5'].append(self.md5checksum(payload))

      else:
        logging.critical("[-] - (Module ShivaParser.py) No match for text/html/content_type or Content-Disposition -")

    return None

    
  def main(self,key, msgMailRequest):
    """This function gets called from server.py module
    """
    #logging.critical("inside mailparser module")
    
    self.mailFields = {'headers':'', 'to':'', 'from':'', 'subject':'', 'date':'', 'firstSeen':'', 'lastSeen':'', 'firstRelayed':'', 'lastRelayed':'', 'sourceIP':'', 'sensorID':'', 'text':'', 'html':'', 'inlineFileName':[], 'inlineFile':[], 'inlineFileMd5':[], 'attachmentFileName':[], 'attachmentFile':[], 'attachmentFileMd5':[], 'links':[], 'ssdeep':'', 'len':'', 's_id':''}
  
    mailFile = open(self.queuepath + "new/" + key,"rb")
    p = email.Parser.Parser()
    msg = p.parse(mailFile)
    mailFile.close()

    f = open(self.queuepath + "new/" + key)
    msgmsg = email.message_from_file(f)
    pp = email.parser.HeaderParser()
    hh = pp.parsestr(msgmsg.as_string())

    headerString = ''
    for h in hh.items():
      headerString += str(h) + '\n'

    self.mailFields['headers'] = headerString
    self.mailFields['headers'] = str(self.mailFields['headers']).replace("'", "")


#
    try:
      try:
        if msg['to'] != None:
          self.mailFields['to'] = parseaddr(msg['to'].replace("'", ""))[1]
        else:
          logging.critical("[-] Info artemismailparser.py - To field has value None")
          self.mailFields['to'] = "-"

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing 'to' field %s" % key)
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing 'to' field %s %s \n" % (key, e))
        return None

      try:
        from_field = msg['from']
            
        if from_field != None:
          self.mailFields['from'] = parseaddr(from_field)[1]
        else:
          logging.critical("[-] Info artemismailparser.py - From field has value None")
          self.mailFields['from'] = "-"

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing 'from' field %s -- %s" % (key, e.args))
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing 'from' field %s %s \n" % (key, e))
        return None

      try:
        subject, encoding = decode_header(msg.get('subject'))[0]                                                                  # Seen cases of unicode. Function returns the encoding type if any

        if encoding == None:
          self.mailFields['subject'] = subject
        else:
          self.mailFields['subject'] = subject.decode(encoding)
          self.mailFields['subject'] = self.mailFields['subject'].encode('utf-8')                                                           # Need to encode('utf-8') else won't be able to push into DB

        if self.mailFields['subject'] != None:
          self.mailFields['subject'] = self.mailFields['subject'].replace("'", "")
          self.mailFields['subject'] = self.mailFields['subject'].replace('"', '')

        else:
          logging.critical("[-] Info artemismailparser.py - Subject field has value None")
          pass

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing 'subject' field %s" % key)
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing 'subject' field %s %s \n" % (key, e))
        return None

      try:
        self.mailFields['sourceIP'] = key.split("-")[-3]
        self.mailFields['sensorID'] = key.split("-")[-2]
        self.mailFields['user'] = key.split("-")[-1]

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing 'sourceIP and sensorID' field %s" % key)
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing 'sourceIP and sensorID' fields %s %s \n" % (key, e))
        return None

      try:
        self.writepartsrecurse(msg)

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in writePartsRecurse function %s -- %s" % (key, e.args))
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in writePartsRecurse function %s %s \n" % (key, e))
        return None

      try:
        if self.mailFields['text'] != None:
          self.mailFields['text'] = self.mailFields['text'].replace("'", "")

        if self.mailFields['html'] != None:
          self.mailFields['html'] = self.mailFields['html'].replace("'", "")

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in 'text' and 'html' field %s" % key)
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in 'text' and 'html' field %s %s \n" % (key, e))
        return None

      # parse different parts of spam (text, html, inline) and hunt for URLs
      try:
        self.mailFields['links'] = self.linkparser(self.mailFields['html'])
        self.mailFields['links'].extend(self.linkparser(self.mailFields['text']))

      except Exception, e:
        logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing 'links' field %s" % key)
        self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing 'links' field %s %s \n" % (key, e))
        return None

      # Timestamping when spam is parsed by our code; not the original time stamping
      self.mailFields['date'] =  datetime.date.today()
      self.mailFields['firstSeen'] =  datetime.datetime.now()
      self.mailFields['lastSeen'] =  datetime.datetime.now()
      self.mailFields['firstRelayed'] =  datetime.datetime.now()
      self.mailFields['lastRelayed'] =  datetime.datetime.now()

      try:
        self.mailFields['ssdeep'] = self.getfuzzyhash()
      except Exception, e:
        logging.critical("[-]Error (Module artemismailparser.py) - occured while calculating fuzzy hash for spam id. %s", e)

      # Calculating md5 of spam which further will be used as unique identifier for a spam.
      if self.mailFields['html']:
        self.mailFields['s_id'] = self.md5checksum(self.mailFields['subject'] + self.mailFields['html'])
      elif self.mailFields['text']:
        self.mailFields['s_id'] = self.md5checksum(self.mailFields['subject'] + self.mailFields['text'])
      else:
        self.mailFields['s_id'] = self.md5checksum(self.mailFields['subject'])

    except Exception, e:
      logging.critical("[-] Error (Module artemismailparser.py) - some issue in parsing file %s %s" % (key, e))
      self.movebadsample(key, "[-] Error (Module artemismailparser.py) - some issue in parsing file %s %s \n" % (key, e))
      return None

    self.concluder.main(self.mailFields, key, msgMailRequest)
    return None
