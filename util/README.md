iana_enterprise_numbers_convert.py
==================================

a script to convert the IANA "enterprise-numbers" to a JSON file

usage:

    rm enterprise-numbers*
    wget http://www.iana.org/assignments/enterprise-numbers
    python iana_enterprise_numbers_convert.py -i enterprise-numbers -o enterprise-numbers.json > debug.txt

then, check the content of the resulting file and move it to aj/app/enterprise-numbers.json
it will be loaded at next restart of Agent-Jones

Ch. Bueche <bueche@netnea.com>
11.7.2014
