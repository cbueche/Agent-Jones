Installation
------------

Installation must be done within a [Python virtual environment](http://www.virtualenv.org/). The goal is to isolate your application from courageous system administrators running OS upgrades without thinking first. The code below is for Python 2.7 on Ubuntu.

    git clone https://github.com/cbueche/Agent-Jones.git
    cd Agent-Jones/aj
    virtualenv --no-site-packages env
    source env/bin/activate
    pip install -U setuptools
    pip install -r ../deployment/requirements.txt

This command will most likely produce a lot of output with warnings, etc. LOok for the following success message at the end :

    Successfully installed Flask Flask-HTTPAuth Flask-RESTful netaddr cffi
    snimpy PyCrypto Exscript ordereddict paramiko MarkupSafe Werkzeug Jinja2
    itsdangerous click aniso8601 six pytz pycparser pysnmp cryptography pyasn1
    python-dateutil pysmi idna enum34 ipaddress ply

Then try to run Agent-Jones :

    python aj.py

It will fail with `ImportError: No module named credentials`. It's a sign of success, now go to the **"Configuration"** part below.

Agent-Jones is a WSGI service within Apache, see the files in deployment/ and the WSGI documentation [here](https://github.com/GrahamDumpleton/mod_wsgi) and [here](http://modwsgi.readthedocs.io/en/develop/).

Platform-specific notes
-----------------------

OS X: run this before "pip":

    export C_INCLUDE_PATH=/opt/local/include (use your correct path, this is for macports)

Ubuntu:

    sudo apt-get install libapache2-mod-wsgi python-virtualenv build-essential python-dev libffi-dev libsmi2-dev git libssl-dev

CentOS 7.x:

    yum install python-virtualenv libffi-devel libsmi-devel openssl-devel

Configuration
-------------

Edit these files to your taste. Copy from the templates and adapt to your own setup.

	app/etc/environment.conf
    app/etc/config.py
    app/etc/credentials.py
    app/etc/enterprise-numbers.json (get it by running ../util/iana_enterprise_numbers_convert.py)
    app/etc/auth_external.py (see below)

The configuration happens with these steps:

- aj.py loads environment.conf to decide where it is running
- the default section of config.py is loaded
- the `environment` section of config.py is loaded

In the simple case, you would have one config.py containing data for each environment. This file can then be deployed to all servers. Beside, the environment.conf is then containing a per-server pointer.

For more complex situations, you would have distinct config.py per environment. Beside, the environment.conf is then containing a per-server pointer.

Authentication
--------------

See the [authentication documentation](authentication.md).
