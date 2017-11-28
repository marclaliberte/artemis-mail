import logging.config, logging.handlers

from artemis.routing import Router, Analyzer_Router
from artemis.server import Relay, SMTPReceiver, QueueReceiver
from artemis.artemisscheduler import Scheduler
from artemis import queue, view

from artemis.analyzer import Analyzer

from config import settings

import jinja2

logging.config.fileConfig("config/logging.conf")

# the relay host to actually send the final message to
settings.relay = Relay(host=settings.relay_config['host'],
                       port=settings.relay_config['port'], debug=1)


settings.analyzer_relay = Relay(host=settings.analyzer_relay_config['host'],
                                port=settings.analyzer_relay_config['port'], debug=0)

# where to listen for incoming messages
settings.receiver = SMTPReceiver(settings.receiver_config['host'],
                                 settings.receiver_config['port'])


settings.analyzer = Analyzer(settings.analyzer_config['queuepath'],
                             settings.analyzer_config['undeliverable_path'],
                             settings.analyzer_config['rawspampath'],
                             settings.analyzer_config['timer'],
                             settings.analyzer_config['attachpath'],
                             settings.analyzer_config['inlinepath'],
                             settings.analyzer_config['relay'],
                             settings.analyzer_config['indivcounter'],
                             settings.analyzer_config['globalcounter'],
                             settings.analyzer_config['hpf_host'],
                             settings.analyzer_config['hpf_port'],
                             settings.analyzer_config['hpf_ident'],
                             settings.analyzer_config['hpf_secret'],
                             settings.analyzer_config['hpfeedattach'],
                             settings.analyzer_config['hpfeedspam'],
                             settings.blackhole_domains)

Analyzer_Router.defaults(**settings.router_defaults)
Analyzer_Router.load(settings.analyzer_handler)
Analyzer_Router.RELOAD = True
Analyzer_Router.UNDELIVERABLE_QUEUE = queue.Queue("run/undeliverable")

Router.defaults(**settings.router_defaults)
Router.load(settings.receiver_handler)
Router.RELOAD = True
Router.UNDELIVERABLE_QUEUE = queue.Queue("run/undeliverable")


view.LOADER = jinja2.Environment(
    loader=jinja2.PackageLoader(settings.template_config['dir'],
                                settings.template_config['module']))
