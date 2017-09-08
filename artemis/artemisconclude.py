"""This module decides that whether a spam is new or old. It checks this by 
comparing the spam against the records which are already there in temporary
list. It first compares Md5 checksum, if not found, it compares against the
SSDEEP hash. If spam is new, it passes it to artemisaddnewrecord module,
for further processing. If it's an old spam, it passes it to artemisprocessold
module.
"""

import logging

import server
import ssdeep

logging.getLogger("analyzer")

class Conclude(object):
  def __init__(self,newrecordhandler,oldrecordhandler):
    self.newrecordhandler = newrecordhandler
    self.oldrecordhandler = oldrecordhandler

  def main(self,mailFields, key, msgMailRequest):
    """Decides if a spam is new or old.
    Takes following parameters:
    a. mailFields - parsed spam fields,
    b. key - spam file name,
    c. msgMailRequest - original spam that is to be relayed.
    
    Passes spam to artemisaddnewrecord module if spam is new or list is empty.
    Else, passes spam to artemisprocessold module.
    """
    logging.info("[+]Inside artemisdecide module.")
    records = server.QueueReceiver.records

    # Checking if we have any item in our global list.
    # If no item: then we will directly push spam details into the list
    # Else: Do the processing.

    if not records:
      self.newrecordhandler.main(mailFields, key, msgMailRequest)

    else:
      if mailFields['text']:
        threshold = 75
      else:
        threshold = 85

      oriLen   = int(mailFields['len'])
      minLen, maxLen = int(oriLen * 0.90), int(oriLen * 1.10)

      count = 0
      for record in records:

        if record['len'] >= minLen and record['len'] <= maxLen:
          if mailFields['s_id'] == record['s_id']:
            self.oldrecordhandler.main(mailFields, record['s_id'], key, msgMailRequest)
            break

          else:
            ratio = ssdeep.compare(mailFields['ssdeep'], record['ssdeep'])

            if ratio >= threshold:
              self.oldrecordhandler.main(mailFields, record['s_id'], key, msgMailRequest)
              break

        count += 1

      if count == len(records):
        self.newrecordhandler.main(mailFields, key, msgMailRequest)
