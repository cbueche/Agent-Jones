#
# aj.wsgi - tells where to find the Agent-Jones application
#

import sys

sys.path.insert(0, '/var/www/aj/AJ/app')

activate_this = '/var/www/aj/AJ/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from aj import app as application
