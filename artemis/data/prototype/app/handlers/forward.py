"""
Implements a forwarding handler that will take anything it receives and
forwards it to the relay host.  It is intended to use with the
artemis.routing.RoutingBase.UNDELIVERABLE_QUEUE if you want mail that Artemis
doesn't understand to be delivered like normal.  The Router will dump
any mail that doesn't match into that queue if you set it, and then you can
load this handler into a special queue receiver to have it forwarded on.

BE VERY CAREFUL WITH THIS.  It should only be used in testing scenarios as
it can turn your server into an open relay if you're not careful.  You
are probably better off writing your own version of this that knows a list
of allowed hosts your machine answers to and only forwards those.
"""

from artemis.routing import route, stateless
from artemis.utils import settings
import logging
import spampot

def forward_handler():
  @route("(to)@(host)", to=".+", host=".+")
  @stateless
  def START(message, to=None, host=None):
    logging.debug("MESSAGE to %s@%s forwarded to the relay host.", to, host)
    settings.relay.deliver(message)
