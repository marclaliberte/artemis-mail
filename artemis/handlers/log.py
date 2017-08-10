"""
Implements a simple logging handler that's actually used by the artemis log
command line tool to run a logging server.  It simply takes every message it
receives and dumps it to the logging.debug stream.
"""

from artemis.routing import route, stateless
import logging
import spampot

def log_handler():
  @route("(to)@(host)", to=".+", host=".+")
  @stateless
  def START(message, to=None, host=None):
    logging.debug("MESSAGE to %s@%s:\n%s", to, host, str(message))


