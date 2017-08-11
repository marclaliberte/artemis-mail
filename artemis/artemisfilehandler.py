"""This module decides that whether a spam is new or old. It checks this by 
comparing the spam against the records which are already there in temporary
list. It first compares Md5 checksum, if not found, it compares against the
SSDEEP hash. If spam is new, it passes it to artemisaddnewrecord module,
for further processing. If it's an old spam, it passes it to artemisprocessold
module.

This module processes file attachments which have already been parsed. Using
hpfeeds it sends full files to the broker.
"""

import logging
import threading
import json
import os
import sys
import shutil
import base64
import hpfeeds.hpfeeds as hpfeeds

class FileHandler(object):
  def __init__(self,hpf_host,hpf_port,hpf_ident,hpf_secret,rawspampath,attachpath,hpfeedspam,hpfeedattach):
    self.hpf_host = hpf_host
    self.hpf_port = hpf_port
    self.hpf_ident = hpf_ident
    self.hpf_secret = hpf_secret
    self.hpf_channels = {'raw_spam': 'artemis.raw', 
                         'attachments': 'artemis.attachments'}
    self.path = {'raw_spam' : rawspampath, 
                 'attach' : attachpath,
                 'hpfeedspam' : hpfeedspam,
                 'hpfeedattach' :hpfeedattach}
    self.lock = threading.Lock()

  def send_attach():
    files = [f for f in os.listdir(path['attach']) if os.path.isfile(os.path.join(path['attach'], f))]
 
    if len(files) > 0:
      for f in files:
        logging.info("Sending attachment %s on hpfeeds channel artemis.attachments" % f)
        spam_id = f.split('-')[0]
        name = f.split('-')[2]

        with open(path['attach']+f) as fp:
          attachment = base64.b64encode(fp.read())

        d = {'s_id': spam_id, 'attachment':attachment, 'name':name}
        data = json.dumps(d)
        with lock:
          hpc.publish(channels['attachments'],data)
          logging.info("[+] Attachment Published")

        shutil.move(path['attach']+f, path['hpfeedattach'])
    else:
      logging.info("Nothing to send on hpfeeds channel artemis.attachments")

  def main():
    try:
      attach_thread = threading.Thread(target = send_attach, args = []).run()
    except Exception, e:
      logging.critical("[-] artemisfilehandler main: Error. %s" % e)


    try:
      while attach_thread.isAlive():
        pass
    except Exception, e:
      pass
