import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

install_requires = [
    'chardet',
    'lmtpd>=4',
    'dnspython',
    'apscheduler==2.1.2',
    'cython==0.20.2',
    'pymongo',
    'ssdeep',
    'docutils',
    'jinja2',
]

if sys.platform != 'win32':  # Can daemonize
    install_requires.append('python-daemon==2.0.2')
else:
    install_requires.append('lockfile')

test_requires = [
    'coverage',
    'jinja2',
    'mock',
]

config = {
    'description': 'A Python honeypot built on Shiva and Salmon',
    'long_description': 'Artemis is a honeynet built using several open source tools',
    'url': 'https://github.com/marclaliberte/artemis-mail',
    'author': 'Zed A. Shaw',
    'maintainer': 'Marc Laliberte',
    'maintainer_email': 'marc@xoro.co',
    'version': '0.1.0',
    'install_requires': install_requires,
    'tests_require': test_requires,
    'setup_requires': ['nose'],
    'test_suite': 'nose.collector',
    'packages': ['artemis', 'artemis.handlers'],
    'include_package_data': True,
    'name': 'artemis-mail',
    'license': 'GPLv3',
    'classifiers': [
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers',
        'Topic :: Communications :: Email',
        'Topic :: Software Development :: Libraries :: Application Frameworks'
        ],
    "entry_points": {
        'console_scripts':
            ['artemis = artemis.commands:main'],
    },
}

setup(**config)
