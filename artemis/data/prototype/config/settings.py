# This file contains python variables that configure Salmon for email processing.

relay_config = {'host': 'localhost', 'port': 8825}
receiver_config = {'host': '0.0.0.0', 'port': 25}

analyzer_relay_config = {'host': 'localhost', 'port': 2500}
analyzer_config = {'attachpath':'attachments/',
                   'inlinepath':'attachments/inline/',
                   'hpfeedattach':'attachments/hpfeedattach/',
                   'queuepath':'queue/',
                   'undeliverable_path':'distorted/',
                   'rawspampath':'rawspams/',
                   'hpfeedspam':'rawspams/hpfeedspam/',
                   'relay':True,
                   'indivcounter':30,
                   'globalcounter':1000,
                   'timer':60,
                   'hpf_host':'tmp.domain.co',
                   'hpf_port':20000,
                   'hpf_ident':'Artemis-Server',
                   'hpf_secret':'SuperSecurePassword',
                   'hpf_channel':{"parsed": "shiva.parsed", "ip_url": "shiva.urls"}}

handlers = ['app.handlers.sample','app.handlers.spampot']
router_defaults = {'host': '.+'}
template_config = {'dir':'app','module':'templates'}

blackhole_emails = []

scheduler_config = {'timer': 60}

# the config/boot.py will turn these values into variables set in settings

