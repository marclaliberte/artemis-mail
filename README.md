Artemis - A Python Mail Honeypot
=============================

Artemis is a python-based honeypot system built using several open source
tools. Artemis-Mail uses the Salmon (fork of Lamson) python mail server along
with code from the Shiva mail honeypot.

Artemis has been released uner the GNU GPLv3, as published by the FSF.

Installing
==========

`apt-get install python g++ python-dev python-pip libmysqlclient-dev make libffi-dev libfuzzy-dev automake autoconf`
`pip install docutils`
`git clone https://github.com/marclaliberte/artemis-mail.git`

`cd artemis-mail`

`python setup.py install`


Setup
==========

`artemis gen artemis`

`cd artemis`
Edit config/settings.py

`artemis start`

Project Information
===================

Source
-----

You can find the source on GitHub:

https://github.com/marclaliberte/artemis-mail

License
----

Artemis is released under the GNU GPLv3 license, which should be included with
your copy of the source code.  If you didn't receive a copy of the license then
you didn't get the right version of the source code.


Security
--------

Artemis follows the same security reporting model that has worked for other open
source projects:  If you report a security vulnerability, it will be acted on
immediately and a fix with complete full disclosure will go out to everyone at
the same time.  It's the job of the people using Salmon to keep track of
security relate problems.

Additionally, Artemis is written in as secure a manner as possible and assumes
that it is operating in a hostile environment.  If you find Artemis doesn't
behave correctly given that constraint then please voice your concerns.



Development
===========

Artemis is written entirely in Python and runs on Python 2.7.
