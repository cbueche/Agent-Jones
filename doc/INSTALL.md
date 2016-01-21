Installation
------------

Installation must be done within a [Python virtual environment](http://www.virtualenv.org/). The goal is to isolate your application from courageaous system administrators running OS upgrades without thinking first.

    /opt/local/bin/virtualenv-2.6 --no-site-packages aj
    cd aj
    source bin/activate
    pip install -r .../deployment/requirements.pip
    pip install PyCrypto
    pip install https://github.com/knipknap/exscript/zipball/master

    rsync -av .../app ./
    python aj.py
    # patch snimpy if needed (only for snimpy version < 0.8.2)
    # https://github.com/vincentbernat/snimpy/commit
    /6857ca3af5ca4858161e7e8e3985bd07ecd7b4a2

Agent-Jones is a WSGI service within Apache, see the files in deployment/ and the [WSGI documentation](https://code.google.com/p/modwsgi/).


Platform-specific notes
-----------------------

OS X: run this before "pip":

    export C_INCLUDE_PATH=/opt/local/include (use your correct path, this is for macports)

Ubuntu: this might not be strictly needed anymore, but I have no fresh system to test. It was needed before I added all needed MIBs. YMMV.

    sudo apt-get install libapache2-mod-wsgi python-virtualenv build-essential python-dev libffi-dev libsmi2-dev git snmp-mibs-downloader



Configuration
-------------

Edit these files to your taste. Copy from the templates and adapt to your own setup.

	app/etc/environment.conf
    app/etc/config.py
    app/etc/credentials.py
    app/etc/enterprise-numbers.json (get it by running ../util/iana_enterprise_numbers_convert.py)

The configuration happens with these steps:

- aj.py loads environment.conf to decide where it is running
- the default section of config.py is loaded
- the `environment` section of config.py is loaded

In the simple case, you would have one config.py containing data for each environment. This file can then be deployed to all servers. Beside, the environment.conf is then containing a per-server pointer.

For more complex situations, you would have distinct config.py per environment. Beside, the environment.conf is then containing a per-server pointer.
