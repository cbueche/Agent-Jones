Installation
------------

Installation must be done within a Python virtual environment. The goal is to isolate your application from courageaous system administrators running OS upgrades without thinking first.

    /opt/local/bin/virtualenv-2.6 --no-site-packages aj
    cd aj
    source bin/activate 
    pip install -r .../deployment/requirements.pip 
    rsync -av .../app ./
    python aj.py

Agent-Jones is a WSGI service within Apache, see the files in deployment/ and the [WSGI documentation](https://code.google.com/p/modwsgi/).


Platform-specific notes
-----------------------

OS X: run this before "pip":

    export C_INCLUDE_PATH=/opt/local/include (use your correct path, this is for macports)


Configuration
-------------

Edit these files to your taste. Copy from the templates and adapt to your own setup.

	app/environment.conf
    app/config.py
    app/credentials.py

The configuration happens with these steps:

- aj.py loads environment.conf to decide where it is running
- the default section of config.py is loaded
- the `environment` section of config.py is loaded

In the simple case, you would have one config.py containing data for each environment. This file can then be deployed to all servers. Beside, the environment.conf is then containing a per-server pointer.

For more complex situations, you would have distinct config.py per environment. Beside, the environment.conf is then containing a per-server pointer.


