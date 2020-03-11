iana_enterprise_numbers_convert.py
==================================

a script to convert the IANA "enterprise-numbers" to a JSON file

usage:

    python iana_enterprise_numbers_convert.py -i http://www.iana.org/assignments/enterprise-numbers -o ./enterprise-numbers.json

then, check the content of the resulting file and move it to `aj/app/etc/enterprise-numbers.json`. It will be loaded at next restart of Agent-Jones

Ch. Bueche <bueche@netnea.com>
22.7.2014
