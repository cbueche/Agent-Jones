Installation
------------

Installation must be done within a [Python virtual environment](http://www.virtualenv.org/). The goal is to isolate your application from courageous system administrators running OS upgrades without thinking first. The code below is for Python 3.7 / 3.8 on Ubuntu.

    git clone https://github.com/cbueche/Agent-Jones.git AJ
    cd AJ
    # choose one of the below
    python3.7 -m venv venv
    python3.8 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install wheel
    pip install -r deployment/requirements.txt

This command will produce a lot of output with warnings, etc. Look for a similar message at the end :

    Successfully installed Exscript-2.6.3 Flask-1.1.1 Flask-HTTPAuth-3.3.0 Flask-RESTful-0.3.8
    Jinja2-2.11.1 MarkupSafe-1.1.1 PyCrypto-2.6.1 Werkzeug-1.0.0 aniso8601-8.0.0 bcrypt-3.1.7
    cffi-1.14.0 click-7.1.1 configparser-4.0.2 cryptography-2.8 future-0.18.2 itsdangerous-1.1.0
    netaddr-0.7.19 ordereddict-1.1 paramiko-2.7.1 ply-3.11 pyasn1-0.4.8 pycparser-2.20
    pycryptodomex-3.9.7 pynacl-1.3.0 pysmi-0.3.4 pysnmp-4.4.12 pytz-2019.3 six-1.14.0 snimpy-0.8.13

Then try to run Agent-Jones :

    python aj/aj.py

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

Edit these files to your taste. Copy from the `etc/templates/` directory and adapt to your own setup.

	app/etc/environment.conf
    app/etc/config.py
    app/etc/credentials.py
    app/etc/enterprise-numbers.json (see below)
    app/etc/auth_external.py (see "Authentication" below)

To get `enterprise-numbers.json`, run this command :

    ../../util/iana_enterprise_numbers_convert.py \
        -i http://www.iana.org/assignments/enterprise-numbers \
        -o enterprise-numbers.json

To give an indication, on 11.3.2020, I got 55'312 entries. You should get a similar number of entries.

At run-time, the configuration happens with these steps:

- aj.py loads environment.conf to decide where it is running
- the default section of config.py is loaded
- the `environment` section of config.py is loaded

In the simple case, you would have one config.py containing data for each environment. This file can then be deployed to all servers. Beside, the environment.conf is then containing a per-server pointer.

For more complex situations, you would have distinct config.py per environment. Beside, the environment.conf is then containing a per-server pointer.

Authentication
--------------

See the [authentication documentation](authentication.md).
