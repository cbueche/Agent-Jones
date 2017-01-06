# Authentication in Agent-Jones

## Introduction

Agent-Jones is a proxy to network devices. As such, the authentication model is an important consideration. There are two sides to consider:

- access to the Agent-Jones web-service
- access to network devices from Agent-Jones

## accessing the Agent-Jones web-service

Agent-Jones is located beyond a WSGI interface, which has to be configured to pass down the Basic-Auth ([RFC 2617](https://www.ietf.org/rfc/rfc2617.txt)) heeaders to the Flask module responsible to check the credentials (flask_httpauth:HTTPBasicAuth). 

For Apache 2.4 and WSGI, the option `WSGIPassAuthorization On` in `deployment/apache_config_example.txt` does exactly this.

Flask receive the Basic-Auth header and pass it to flask_httpauth for checking. The very simple get_verify_password() function in aj.py transmit the credentials along with the request object to AuthExternal.verify_credentials(). This function must be defined in etc/auth_external.py and can be as simple or complex as desired. A template to get started is located in etc/templates/auth_external_template.py.

The template shows a cascade of successive checks: REMOTE_ADDR, BasicAuth, ICAP's X-Authenticated-User. Your final code is your business, but basically, return `True` to signal a successful login or `False` to deny access.

## Agent-Jones accessing the network devices

For each operation on a network device (except maybe a `ping`), Agent-Jones must know the device's credentials. The functionality is implemented as a callback. First, in aj.py, at the start of an API call processing, AJ creates a Snimpy manager:

    m = snimpy.create(devicename=devicename)

The call aboves provides a read-only manager (if using SNMPv2). A possibility exists to add a `rw` option to get a read-write manager.

    m = snimpy.create(devicename=devicename, rw=True)

While creating the manager instance, the callback `get_credentials()` is called with the device name as only parameter:

	credentials = self.credmgr.get_credentials(devicename)

`get_credentials()` is loaded from `app/etc/credentials.py`. It is your responsability to code this file. A very simple example is located in `app/etc/templates/credentials_template.py`, which must be edited and copied to `app/etc/credentials.py`.

The `get_credentials()` method can be as complex as you want, but be aware that it is called a lot, so it should preferably be efficient and not rip down a remote CMDB.