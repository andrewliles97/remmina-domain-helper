#!/usr/bin/python

# Remmina domain helper
# (c) 2014 Andrew Liles

# Makes life a little easier when changing passwords on Active Directory domains
# Finds all Remmina config files for hosts within that domain
# that don't have a matching password and optionally updates them.

import sys
import getopt
import os
import base64
import ConfigParser
import glob
import getpass
from Crypto.Cipher import DES3

savePass = False

# Probably not necessary, but to match the INI format of the files remmina writes:
# http://stackoverflow.com/a/25084055
class EqualsSpaceRemover:
    output_file = None

    def __init__(self, new_output_file):
        self.output_file = new_output_file

    def write(self, what):
        self.output_file.write(what.replace(" = ", "="))


def usage():
    print "usage: {} [-s] <domain>".format(os.path.basename(__file__))


try:
    opts, args = getopt.getopt(sys.argv[1:], "s")
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(2)

for o, a in opts:
    if o == "-s":
        savePass = True
    else:
        assert False, "unexpected option"

if len(args) != 1:
    usage()
    sys.exit(2)

domain = str(args[0]).lower()

if not domain:
    usage()
    sys.exit(2)

if savePass:
    newpass = getpass.getpass("New password: ")
    newpassconfirm = getpass.getpass("Confirm: ")

    if newpass != newpassconfirm:
        print "Passwords do not match."
        exit()

    del newpassconfirm
else:
    newpass = getpass.getpass("Password: ")

if not newpass:
    print "Password is empty."
    exit()

masterconfig = ConfigParser.ConfigParser()
masterconfig.read(os.path.expanduser("~/.remmina/remmina.pref"))
secret = base64.decodestring(masterconfig.get("remmina_pref", "secret"))

des = DES3.new(secret[:24], DES3.MODE_CBC, secret[24:])
padlength = 8 - (len(newpass) % 8)
cryptedpass = base64.b64encode(des.encrypt(newpass + ('\0' * padlength)))
del newpass, masterconfig, secret, des, padlength

filesToUpdate = {}

rds = glob.glob(os.path.expanduser("~/.remmina") + "/*.remmina")
for rd in rds:
    remmfile = ConfigParser.ConfigParser()
    remmfile.read(rd)
    rtype = remmfile.get("remmina", "protocol")
    if rtype != 'RDP':
        continue
    thisdomain = remmfile.get("remmina", "domain")
    if thisdomain.lower() != domain:
        continue
    host = remmfile.get("remmina", "server")
    thispass = remmfile.get("remmina", "password")
    if thispass != cryptedpass:
        filesToUpdate[host] = rd

    # don't need to actually decode passwords since they are unsalted and crypted with same key
    # comparing the hashes is sufficient

    # des = DES3.new(secret[:24], DES3.MODE_CBC, secret[24:])
    # clearpass = des.decrypt(base64.b64decode(thispass)).rstrip('\0')

    if not savePass:
        print "Host: {} Password Matches: {}".format(host, str(thispass == cryptedpass))

if savePass:
    if len(filesToUpdate.keys()) > 0:
        print "Updating the following hosts:"
        print ", ".join(filesToUpdate.keys())
        response = raw_input("OK to proceed? [y/N]: ")
        if response and response[0].lower() == 'y':
            for host in filesToUpdate:
                cfgparse = ConfigParser.RawConfigParser(allow_no_value=True)
                cfgparse.read(filesToUpdate[host])
                cfgparse.set("remmina", "password", cryptedpass64)
                with open(filesToUpdate[host], "w") as cfgwrite:
                    cfgparse.write(EqualsSpaceRemover(cfgwrite))
                print "Updated password for {}".format(host)
        else:
            print "Operation canceled."
    else:
        print "No hosts to update."
