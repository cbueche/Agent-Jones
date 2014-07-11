#!/usr/bin/python
#
# iana_enterprise_numbers_convert.py
# a script to convert the IANA "enterprise-numbers" to a JSON file
#
# Ch. Bueche <bueche@netnea.com>
# 11.7.2014
#
# --------------------------------------------------------------------------------
# usage:
# wget http://www.iana.org/assignments/enterprise-numbers
# python iana_enterprise_numbers_convert.py -i enterprise-numbers -o enterprise-numbers.json > debug.txt
# --------------------------------------------------------------------------------


from optparse import OptionParser
import sys
import re
import json


# --------------------------------------------------------------------------------
def main():
# --------------------------------------------------------------------------------

    # script parameters
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", default="", help="input file")
    parser.add_option("-o", "--output", dest="output", default="", help="output file")
    (params, args) = parser.parse_args()
    input_file = params.input
    output_file = params.output
    print "input = %s, output = %s" % (input_file, output_file)

    # conversion
    entries = iana_to_json(input_file, output_file)
    print "entries = %s" % entries


# --------------------------------------------------------------------------------
def iana_to_json(input_file, output_file):
# --------------------------------------------------------------------------------

    # input file
    try:
        fp = open(input_file, 'r')
    except e:
        print "ERROR : cannot open input file, exit : %s" % e
        sys.exit(1)

    # read until the data start (0 - Reserved)
    while True:
        line = fp.readline()
        if not line: break

        # remove end of line
        line = line.rstrip()

        print "LINE = <%s>" % line

        # header parsing
        # --------------

        # check for the usual IANA header in 1st line
        if re.search(r'PRIVATE ENTERPRISE NUMBERS', line):
            print "found header"

        # last updated stamp
        regex = re.compile(r'\(last updated (\d{4}-\d{2}-\d{2})\)')
        match = regex.search(line)
        if match:
            last_update = match.group(1)
            print "updated = %s" % last_update

        # stop right before the data records
        if line == '| | | |':
            break

    print "header done"

    # and now the data

    record_fields = 0
    last_match = ''
    valid_entries = 0
    enterprises = {}
    while True:

        line = fp.readline().strip('\n')

        # skip blank lines
        if line == '':
            print "BLANK"
            continue

        if not line:
            print "no line, break"
            break
        print "LINE : <%s>" % line

        # try to identify breakages beyond repair
        # odd number of spaces
        if re.search(r'^ \S', line) or re.search(r'^   \S', line) or re.search(r'^     \S', line) or re.search(r'^       \S', line):
            print "ERROR : uneven number of spaces at start of line : <%s>" % line
            # continue to next valid record
            # we consume the file until the end of the current or next record
            while True:
                line = fp.readline().strip('\n')
                if re.search(r'^      \S.*$', line):
                    print "drop line : <%s>" % line
                    break
            record_fields = 0
            print "back to next record"
            continue

        # get decimal
        if re.search(r'^\d+$', line):
            print "found decimal"
            decimal = line.strip()
            record_fields += 1
            last_match = 'decimal'

        # get organization
        if re.search(r'^  \S.*$', line) or line == '  ':
            print "found organization"
            organization = line.strip()
            record_fields += 1
            last_match = 'organization'

        # get contact
        if re.search(r'^    \S.*$', line) or line == '    ':
            print "found contact"
            contact = line.strip()
            record_fields += 1
            last_match = 'contact'

        # get email
        if re.search(r'^      \S.*$', line) or line == '      ':
            print "found email"
            email = line.strip()
            record_fields += 1
            last_match = 'email'
            if record_fields != 4:
                print "ERROR : un-synced"

        # get line addition
        # any non-blank text starting at beginning of line, but not a number
        if re.search(r'^[^\d\s]', line):
            print "addition"
            if last_match == 'decimal':
                print "ERROR : do not want to add to decimal : line = <%s>" % line
            if last_match == 'organization':
                organization = organization + ' ' + line
            if last_match == 'contact':
                contact = contact + ' ' + line
            if last_match == 'email':
                email = email + ' ' + line

        if record_fields == 4:
            email = email.replace('&', '@')
            print "decimal = <%s>, organization = <%s>, contact = <%s>, email = <%s>" % (decimal, organization, contact, email)
            enterprises[decimal] = {'o': organization, 'c': contact, 'e': email}
            valid_entries += 1
            decimal = ''
            organization = ''
            contact = ''
            email = ''
            record_fields = 0

        # check for the usual IANA footer in last line
        if re.search(r'End of Document', line):
            print "found footer"
            break

    fp.close

    # write structure to output file
    with open(output_file, 'w') as of:
      json.dump(enterprises, of)

    return valid_entries


# --------------------------------------------------------------------------------
if __name__ == "__main__":
# --------------------------------------------------------------------------------
    main()
