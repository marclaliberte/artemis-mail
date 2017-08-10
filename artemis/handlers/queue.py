"""
Implements a handler that puts every message it receives into 
the run/queue directory.  It is intended as a debug tool so you
can inspect messages the server is receiving using mutt or 
the artemis queue command.
"""

from artemis.routing import route_like, stateless, nolocking, route
from artemis import queue, handlers
import logging
import re
import spampot

def queue_handler():
  @route("(to)@(host)", to=".+", host=".+")
  @stateless
  @nolocking
  def START(message, to=None, host=None):
    q = queue.Queue(spampot.pathOfQueue)
    email = "%s@%s" % (to, host)
    message = str(message).replace("%", "%%")
    new_msg = re.sub(r'(?m)^\To:.*\n?', 'To: {0}\n', message, 1).format(email)
    q.push(new_msg)

