#!/usr/bin/python
#
# Copyright (c) 2012 Attila Lendvai
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Invoke with ./gpg-genkey --help to see usage.
#
# generates
# - three passphrases (for the master and the 2 subkeys)
# - an RSA 8192 signing master key,
# - one encryting and one signing subkey
# - an encrypted revocation cert for the masterkey
# - the key for the revocation cert in 5 ssss shares
# - an encrypted copy of the masterkey for backup
# - the key for the backup in 5 ssss shares
#
# depends: gnupg, openssl, ssss, gpgsplit, srm
# on Debian:
# sudo apt-get install gnupg secure-delete ssss

import os, sys, subprocess
import types, traceback
import tempfile
import argparse

identityName            = "John Doe"
identityComment         = "master key"               # your nickname and/or comment
identityEmail           = "jd@example.com"

keyType                 = "RSA"                      # DSA is too small

masterKeyLength           = "8192"                   # enlarge your keysize! (gpg can handle 8192+ bit keys once they got generated)
masterphraselen           = "5"                      # 5 words is a minimum
masterKeyExpire           = "0"                      # Master key should never expire

signingSubkeyLength       = "2048"
signingSubkeyExpire       = "5y"

encryptionSubkeyLength    = "4096"
encryptionSubkeyExpire    = "5y"

def printLogLine(message):
    # syslog.syslog(level, "syncman: " + formattedMessage)
    sys.stderr.write("*** " + message + "\n")

def log(message, *args):
    printLogLine(message % args)

def logError(message, *args):
    exception = None
    if isinstance(message, Exception):
        exception = message
        args = list(args)
        message = args.pop()
        args = tuple(args)
    print(args)
    log(message % args)
    if exception:
        etype, evalue, etraceback = sys.exc_info()
        logException(etype, evalue, etraceback)

def logException(etype, evalue, etb):
    for line in traceback.format_exception(etype, evalue, etb):
        for line in line.rstrip().splitlines():
            printLogLine(line)

def ensureDirectoryExists(path):
    if not os.path.exists(path):
        os.makedirs(path, mode = 0700)
    return path

def isEmpty(thing):
    return not isinstance(thing, str) or thing == ""

class ShellCommandError(Exception):
    def __init__(self, command, returnCode, stdout, stderr):
        self.command = command
        self.returnCode = returnCode
        self.stdout = stdout
        self.stderr = stderr
    def __str__(self):
        return "Shell command returned with return code: " + str(self.returnCode) + "\nstdout: {{{" + self.stdout + "}}}, stderr: {{{" + self.stderr + "}}}"

def run(command, **kwargs):
    filteredKwargs = dict(kwargs)
    map(lambda key: filteredKwargs.pop(key, None), ["printCommand", "ignoreErrors", "input"])

    stdin = ""
    filteredKwargs["shell"]  = kwargs.get("shell", True)
    filteredKwargs["stdout"] = kwargs.get("stdout", subprocess.PIPE)
    filteredKwargs["stderr"] = kwargs.get("stderr", subprocess.PIPE)
    if isinstance(kwargs.get("stdin"), str):
        filteredKwargs["stdin"] = subprocess.PIPE
        stdin = kwargs.get("stdin")

    process = subprocess.Popen(command, **filteredKwargs)
    if kwargs.get("printCommand", False):
        print("# " + command)

    stdout, stderr = process.communicate(stdin)
    if not kwargs.get("ignoreErrors", False) and process.returncode != 0:
        raise ShellCommandError(command, process.returncode, stdout, stderr)
    return stdout, stderr

def gpgCommandLine(*args):
    line = "gpg2 --no-default-keyring --homedir '" + gpgHomeDirectory + "'"
    for arg in args:
        line += " " + arg
    return line

def runGpg(*args, **kwargs):
    return run(gpgCommandLine(*args), **kwargs)[0]

def runGpgWithoutCapturing(*args, **kwargs):
    return run(gpgCommandLine(*args), stdout = sys.stdout, stderr = sys.stderr, **kwargs)

def getMasterKeyFingerprint(**kwargs):
    failIfMissing = kwargs.get("failIfMissing", True)
    output = runGpg("--with-colons --list-secret-keys").splitlines()
    output = [line for line in output if line.startswith("sec:")]
    if len(output) > 1:
        raise Exception("Multiple master keys in the secring?")
    elif len(output) == 0:
        if failIfMissing:
            raise Exception("No master key found in the secring.")
        else:
            return None
    columns = output[0].split(":")
    shortFingerprint = columns[4]

    output = runGpg("--with-colons --fingerprint --list-secret-keys", shortFingerprint).splitlines()
    assert(len(output) > 1)
    assert(output[1].startswith("fpr:"))
    columns = output[1].split(":")

    return columns[9]

def generateMasterKey():
    if getMasterKeyFingerprint(failIfMissing = False) != None:
        raise Exception("There's already a master key in the secring, this script doesn't support that use-case.")

    stdinBuffer = ""
    for entry in [
                     "Key-Type: " + keyType,
                     "Key-Length: " + masterKeyLength,
                     "Key-Usage: sign",
                     "Expire-Date: " + masterKeyExpire,
                     (not isEmpty(identityName),    "Name-Real: "    + identityName),
                     (not isEmpty(identityComment), "Name-Comment: " + identityComment),
                     (not isEmpty(identityEmail),   "Name-Email: "   + identityEmail),
                     #(not isEmpty(masterKeyPassphrase), "Passphrase: " + masterKeyPassphrase),
                     #(isEmpty(masterKeyPassphrase), "%ask-passphrase"),
                     "%ask-passphrase",
                     "%commit"
                 ]:
        if type(entry) == types.TupleType:
            if entry[0]:
                stdinBuffer += entry[1] + "\n"
        else:
            stdinBuffer += entry + "\n"

    log("Calling gpg to generate the master signing key. You will be asked for a passphrase to encrypt it. Generation may take a while due to collecting entropy...")

    runGpgWithoutCapturing("--batch --gen-key", stdin = stdinBuffer)

def generateRevocationCertificate():
    fingerprint = getMasterKeyFingerprint()
    fileNameBase = "revocation-certificate-for-" + fingerprint[-8:]
    fileNameCleartext = fileNameBase + "-cleartext.gpg"
    fileNamePassphrase = fileNameBase + "-passphrase-protected.gpg"

    log("Calling gpg to generate the revocation certificate. You may be asked for your master key passphrase, and will be asked for a passphrase to (symmetrically) encrypt your revocation certificate. You can decrypt using gpg --decrypt and this passphrase if/when the certificate is needed.")

    runGpgWithoutCapturing("--output '" + workingDirectory + "/tmp/" + fileNameCleartext + "'",
                           "--command-fd 0",
                           "--gen-revoke " + fingerprint,
                           stdin = "y\n1\nRevocation certificate automatically generated at key generation time.\n\ny\n")

    # symmetrically encrypt the revocation certificate
    runGpgWithoutCapturing("--symmetric ",
                           "--output '" + workingDirectory + "/" + fileNamePassphrase + "'",
                           "'" + workingDirectory + "/tmp/" + fileNameCleartext + "'")

def generateSubkeys():
    fingerprint = getMasterKeyFingerprint()

    log("About to generate the subkeys, your master key passphrase will be needed.")

    runGpg("--command-fd 0",
           "--quiet",
           "--yes",
           "--edit-key " + fingerprint,
           stdin = "addkey\n6\n" + encryptionSubkeyLength + "\n" + encryptionSubkeyExpire + "\n" +
                   "addkey\n4\n" + signingSubkeyLength +    "\n" + signingSubkeyExpire +    "\nsave\n")

def exportKeys():
    log("About to export keys.")

    fingerprint = getMasterKeyFingerprint()
    fingerprintShort = fingerprint[-8:]

    fileName = "secret-subkeys-" + fingerprintShort

    runGpg("--quiet --batch --yes",
           "--output '" + workingDirectory + "/secret-subkeys.gpg'",
           "--export-secret-subkeys " + fingerprint)

    runGpg("--quiet --batch --yes",
           "--output '" + workingDirectory + "/secret-master-key.gpg'",
           "--export-secret-keys " + fingerprint)

    runGpg("--quiet --batch --yes",
           "--output '" + workingDirectory + "/public-keys.gpg'",
           "--export " + fingerprint)

    log("Exporting done.")

try:
    argParser = argparse.ArgumentParser(description = 'Generate PGP key using GnuPG. See the front of the source code for the key parameters.')
    argParser.add_argument('command',           metavar='command',         type = str, nargs = "?", default = "wholeStory", help = 'Command to run (see source code for a full list). Defaults to run the whole story and generate a key from zero.')
    argParser.add_argument('--tmpdir',          metavar='tmpdir',          type = str, nargs = 1, help = "Defaults to /run/shm/gpg-key-gen{random}. Should be a volatile storage that doesn't get written to disk, or otherwise 'srm' (secure-delete) should be used for removing the sensitive data.")

    args = argParser.parse_args()

    if args.tmpdir:
        workingDirectory = ensureDirectoryExists(args.tmpdir[0])
    else:
        workingDirectory = tempfile.mkdtemp(dir = "/run/shm", prefix = "gpg-key-gen")

    gpgHomeDirectory = ensureDirectoryExists(workingDirectory + "/tmp/gpg-homedir")

    open(gpgHomeDirectory + "/gpg.conf", "w").write("""personal-digest-preferences SHA512
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed""")

    log("Temporary directory for sensitive data will be: '" + workingDirectory + "'. Make sure it's either in a volatile storage (e.g. /run/shm/ on linux), or it's deleted using 'srm' (secure-delete) once it's not needed!")

    if args.command == "wholeStory":
        log("You will repeatedly be asked for passphrases in blocking windows, so it's a good idea to keep the messages in this window visible.")
        generateMasterKey()
        log("Master signing key generated, fingerprint is '%s', details follow.", getMasterKeyFingerprint())
        runGpgWithoutCapturing("--list-secret-keys")
        generateRevocationCertificate()
        generateSubkeys()
        exportKeys()

        resultDirectory = workingDirectory
        if not args.tmpdir:
            fingerprint = getMasterKeyFingerprint()
            newName = os.path.join(os.path.dirname(workingDirectory), "gpg-key-" + fingerprint)
            os.rename(workingDirectory, newName)
            resultDirectory = newName
        log("Done, your keys have been exported to '%s'. Now you can import the public keys and the secret subkeys to your regularly used device(s) (gpg --import public-keys.gpg secret-subkeys.gpg), but only import the secret part of the master key into a safe location (gpg --homedir some/safe/location --import public-keys.gpg secret-subkeys.gpg secret-master-key.gpg).",
            resultDirectory)
    elif args.command == "generateMasterKey":
        generateMasterKey()
    elif args.command == "generateSubkeys":
        generateSubkeys()
    elif args.command == "generateRevocationCertificate":
        generateRevocationCertificate()
    elif args.command == "exportKeys":
        exportKeys()
    elif args.command == "getMasterKeyFingerprint":
        print(getMasterKeyFingerprint(failIfMissing = False))
    else:
        log("Error, unknown command '%s'", args.command)

except Exception as e:
    logError(e, "Error reached toplevel, exiting.")
