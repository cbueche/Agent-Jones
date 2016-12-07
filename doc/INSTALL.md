Installation
------------

Installation must be done within a [Python virtual environment](http://www.virtualenv.org/). The goal is to isolate your application from courageous system administrators running OS upgrades without thinking first. The code below is for Python 2.6 on Ubuntu 10.04, but it has been working fine on Ubuntu 14.04 with Python 2.7.

    /opt/local/bin/virtualenv-2.6 --no-site-packages aj
    cd aj
    source bin/activate
    pip install -U setuptools
    pip install -r .../deployment/requirements.pip

    rsync -av .../app ./
    python aj.py
    # patch snimpy if needed (only for snimpy version < 0.8.2)
    # https://github.com/vincentbernat/snimpy/commit
    /6857ca3af5ca4858161e7e8e3985bd07ecd7b4a2

[This other patch](https://github.com/vincentbernat/snimpy/commit/d3a36082d417bb451e469f33938e1d0821b615ea) might be needed if you get `prettyOut` from a SNMP-get on sysObjectID or another similar get returning an OID.

File : site-packages/snimpy/snmp.py

    --- snmp.py.sav	2016-01-29 10:53:47.112808191 +0100
    +++ snmp.py	2016-01-29 10:54:48.817420481 +0100
    @@ -215,6 +215,12 @@

         def _convert(self, value):
             """Convert a PySNMP value to some native Python type"""
    +        try:
    +            # With PySNMP 4.3+, an OID is a ObjectIdentity. We try to
    +            # extract it while being compatible with earlier releases.
    +            value = value.getOid()
    +        except AttributeError:
    +            pass
             for cl, fn in {rfc1902.Integer: int,
                            rfc1902.Integer32: int,
                            rfc1902.OctetString: bytes,

Agent-Jones is a WSGI service within Apache, see the files in deployment/ and the [WSGI documentation](https://code.google.com/p/modwsgi/).


Platform-specific notes
-----------------------

OS X: run this before "pip":

    export C_INCLUDE_PATH=/opt/local/include (use your correct path, this is for macports)

Ubuntu: this might not be strictly needed anymore, but I have no fresh system to test. It was needed before I added all needed MIBs. YMMV.

    sudo apt-get install libapache2-mod-wsgi python-virtualenv build-essential python-dev libffi-dev libsmi2-dev git snmp-mibs-downloader libssl-dev


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
