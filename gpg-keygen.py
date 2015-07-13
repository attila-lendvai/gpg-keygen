#!/usr/bin/env python3
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
# To install dependencies on Debian run:
# sudo apt-get install openssl gnupg secure-delete ssss

import os, sys, subprocess
import types, traceback
import tempfile
import argparse

gpgHomeDirectory = None
workingDirectory = None

ssssIsAvailable           = False                     # [doesn't work yet] this is merely a default, will later be checked by code that tries to run "ssss-split -v"
revocationCertificateShares       = 5
revocationCertificateSharesNeeded = 4

def printLogLine(message):
    # syslog.syslog(level, "gpg-keygen: " + formattedMessage)
    sys.stderr.write("*** " + message + "\n")

def log(message, *args):
    printLogLine(message % args)

def logError(message, *args):
    exception = None
    if isinstance(message, Exception):
        exception = message
        args = list(args)
        message = args.pop(0)
        args = tuple(args)
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
        os.makedirs(path, mode = 0o700)
    return path

def isEmpty(thing):
    return not isinstance(thing, str) or thing == ""

class UserMessageError(Exception):
    def __init__(self, message, *args):
        self.message = message
        self.args = args
    def __str__(self):
        return self.message % self.args

class ShellCommandError(Exception):
    def __init__(self, command, returnCode, stdout, stderr):
        self.command = command
        self.returnCode = returnCode
        self.stdout = stdout
        self.stderr = stderr
    def __str__(self):
        return "Shell command returned with return code: " + str(self.returnCode) + "\nstdout: {{{" + str(self.stdout) + "}}}, stderr: {{{" + str(self.stderr) + "}}}"

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

    #log("exec'ing the following: '%s'", command)

    process = subprocess.Popen(command, **filteredKwargs)
    if kwargs.get("printCommand", False):
        print("# " + command)

    stdout, stderr = process.communicate(input = bytes(stdin, 'UTF-8'))
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
    output = [line for line in output if line.startswith(bytes("sec:", 'UTF-8'))]
    if len(output) > 1:
        raise UserMessageError("Multiple master keys in the secring!?")
    elif len(output) == 0:
        if failIfMissing:
            raise UserMessageError("No master key found in the secring.")
        else:
            return None
    columns = output[0].split(bytes(":", 'UTF-8'))
    shortFingerprint = columns[4]

    output = runGpg("--with-colons --fingerprint --list-secret-keys", str(shortFingerprint, 'UTF-8')).splitlines()
    assert(len(output) > 1)
    assert(output[1].startswith(bytes("fpr:", 'UTF-8')))
    columns = output[1].split(bytes(":", 'UTF-8'))

    return str(columns[9], 'UTF-8')

def generateMasterKey(args):
    if getMasterKeyFingerprint(failIfMissing = False) != None:
        raise UserMessageError("There's already a master key in the gpg secring, this script doesn't support that use-case.")

    if not args.identityName:
        raise UserMessageError("the --identity-name parameter is mandatory when generating a master key")

    stdinBuffer = ""
    for entry in [
                     "Key-Type: " + args.masterKeyType,
                     "Key-Length: " + str(args.masterKeyLength),
                     "Key-Usage: sign",
                     "Expire-Date: " + args.masterKeyExpire,
                     "Name-Real: " + args.identityName,
                     (not isEmpty(args.identityComment), "Name-Comment: " + args.identityComment),
                     (not isEmpty(args.identityEmail),   "Name-Email: "   + args.identityEmail),
                     #(not isEmpty(masterKeyPassphrase), "Passphrase: " + masterKeyPassphrase),
                     #(isEmpty(masterKeyPassphrase), "%ask-passphrase"),
                     "%ask-passphrase",
                     "%commit"
                 ]:
        if type(entry) == tuple:
            if entry[0]:
                stdinBuffer += entry[1] + "\n"
        else:
            stdinBuffer += entry + "\n"

    log("Calling gpg to generate the master signing key. You will be asked for a passphrase to encrypt it. Generation may take a while due to collecting entropy, especially for long keys. Be patient...")

    runGpgWithoutCapturing("--batch --verbose --gen-key", stdin = stdinBuffer)

    log("Master signing key has successfully been generated, its fingerprint is '%s', details follow.", getMasterKeyFingerprint())
    runGpgWithoutCapturing("--list-secret-keys")

def generateRevocationCertificate(args):
    fingerprint = getMasterKeyFingerprint()
    fileNameBase = "revocation-certificate-for-" + fingerprint[-8:]
    fileNameCleartext = fileNameBase + "-cleartext.gpg"
    fileNamePassphrase = fileNameBase + "-passphrase-protected.gpg"
    fileNameSsss = fileNameBase + "-ssss-protected.gpg"

    log("Calling gpg to generate the revocation certificate. You may be asked for your master key passphrase, and you will be asked for a passphrase to (symmetrically) encrypt your revocation certificate. If/when the certificate is needed in the future, then you can decrypt it using 'gpg --decrypt' and providing this passphrase.")

    runGpgWithoutCapturing("--output '" + workingDirectory + "/tmp/" + fileNameCleartext + "'",
                           "--command-fd 0",
                           "--gen-revoke " + fingerprint,
                           stdin = "y\n1\nRevocation certificate automatically generated when the PGP key itself was generated.\n\ny\n")

    # symmetrically encrypt the revocation certificate
    runGpgWithoutCapturing("--symmetric ",
                           "--output '" + workingDirectory + "/" + fileNamePassphrase + "'",
                           "'" + workingDirectory + "/tmp/" + fileNameCleartext + "'")

    if ssssIsAvailable:
        ssssKey = run("openssl rand -hex 128")[0]
        if ssssKey.endswith("\n"):
            ssssKey = ssssKey[:-1]
        assert(len(ssssKey) == 256)
        runGpgWithoutCapturing("--passphrase='" + ssssKey + "'"
                               "--batch",
                               "--output '" + workingDirectory + "/" + fileNameSsss + "'",
                               "--symmetric",
                               "'" + workingDirectory + "/tmp/" + fileNameCleartext + "'")
        # TODO fixme: i can't make ssss-split stop asking for more characters when reading the secret from stdin, and there's no command line parameter for the secret
        print("ssss-split -x -n " + str(revocationCertificateShares) + " -t " + str(revocationCertificateSharesNeeded))
        #print(run("echo '" + ssssKey + "' | ssss-split -x -n " + str(revocationCertificateShares) + " -t " + str(revocationCertificateSharesNeeded), stderr = sys.stderr, stdout = sys.stdout)[0])
        print(run("ssss-split -x -n " + str(revocationCertificateShares) + " -t " + str(revocationCertificateSharesNeeded), stdin = ssssKey + '\n\n\n\n\n', stderr = sys.stderr, stdout = sys.stdout)[0])
        #run("ssss-split -x -n " + str(revocationCertificateShares) + " -t " + str(revocationCertificateSharesNeeded), stdin = sys.stdin, stderr = sys.stderr, stdout = sys.stdout)
        #print(run("wc -c", stdin = "alma")[0])

def generateSubkeys(args):
    fingerprint = getMasterKeyFingerprint()

    log("About to generate the subkeys, your master key passphrase will be needed.")

    runGpg("--command-fd 0",
           "--quiet",
           "--yes",
           "--edit-key " + fingerprint,
           stdin = "addkey\n6\n" + str(args.encryptionSubkeyLength) + "\n" + args.encryptionSubkeyExpire + "\n" +
                   "addkey\n4\n" + str(args.signingSubkeyLength) +    "\n" + args.signingSubkeyExpire +    "\nsave\n")

def exportKeys(args):
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

def generateEverything(args):
    log("You will repeatedly be asked for various passphrases in blocking windows, so it's a good idea to keep the log messages in this window visible.")
    generateMasterKey(args)
    generateRevocationCertificate(args)
    generateSubkeys(args)
    exportKeys(args)

    resultDirectory = workingDirectory
    # optionally rename temporary directory to contain the key fingerprint (if not user specified)
    if not args.temporaryDirectory:
        fingerprint = getMasterKeyFingerprint()
        newName = os.path.join(os.path.dirname(workingDirectory), "gpg-key-" + fingerprint)
        os.rename(workingDirectory, newName)
        resultDirectory = newName

    log("Done, your keys have been exported to '%s'. Now you can import the public keys and the secret subkeys to your regularly used device(s) (gpg --import public-keys.gpg secret-subkeys.gpg), but only import the secret part of the master key into a safe location (gpg --homedir some/safe/location --import public-keys.gpg secret-subkeys.gpg secret-master-key.gpg).",
        resultDirectory)

try:
    if sys.version_info < (2, 7):
        log("WARNING: this script was written and tested using python v2.7 and you seem to be running something older.")

    argParser = argparse.ArgumentParser(description = 'Generate a new PGP key with GnuPG using current best practices (notwithstanding some subjectivity).',
                                        formatter_class = argparse.ArgumentDefaultsHelpFormatter)
    argParser.add_argument('--temporary-directory', "-t", metavar = 'DIR', dest = 'temporaryDirectory', type = str, help = "Defaults to /run/shm/gpg-key-gen{random}. Should point to a volatile storage, or otherwise 'srm' (secure-delete) should be used for removing the sensitive data from non-volatile storage devices.")

    argGroup = argParser.add_argument_group(title = 'Master key')
    argGroup.add_argument('--master-key-length',     metavar = 'BITS', dest = 'masterKeyLength',      type = int, default = 8192,  help = 'Master key length')
    argGroup.add_argument('--master-key-type',       metavar = 'TYPE', dest = 'masterKeyType',        type = str, default = "RSA", help = 'Master key type')
    argGroup.add_argument('--master-key-expire',     metavar = 'EXP',  dest = 'masterKeyExpire',      type = str, default = "0",   help = 'Master key expiration date. Zero means never expires.')

    argGroup = argParser.add_argument_group(title = 'An email identity')
    argGroup.add_argument('--identity-name',    metavar = 'NAME',    dest = 'identityName',    type = str, default = None,      help = 'The real name part.')
    argGroup.add_argument('--identity-comment', metavar = 'COMMENT', dest = 'identityComment', type = str, default = "",        help = 'The comment part.')
    argGroup.add_argument('--identity-email',   metavar = 'EMAIL',   dest = 'identityEmail',   type = str, default = "",        help = 'The email part.')

    argGroup = argParser.add_argument_group(title = 'Subkeys')
    argGroup.add_argument('--encryption-subkey-length', metavar = 'BITS', dest = 'encryptionSubkeyLength', type = int, default = 4096, help = 'Encryption subkey length.')
    argGroup.add_argument('--encryption-subkey-expire', metavar = 'EXP',  dest = 'encryptionSubkeyExpire', type = str, default = "3y", help = 'Encryption subkey expiration date. Zero means never expires.')
    argGroup.add_argument('--signing-subkey-length',    metavar = 'BITS', dest = 'signingSubkeyLength', type = int, default = 2048, help = 'Signing subkey length.')
    argGroup.add_argument('--signing-subkey-expire',    metavar = 'EXP',  dest = 'signingSubkeyExpire', type = str, default = "3y", help = 'Signing subkey expiration date. Zero means never expires.')

    argParser.add_argument('--step', choices=['generateMasterKey', 'generateSubkeys', 'generateRevocationCertificate', 'exportKeys'], help = "Which step to run. If none given then all of them will be run.")

    args = argParser.parse_args()

    if args.temporaryDirectory:
        workingDirectory = ensureDirectoryExists(args.temporaryDirectory)
    else:
        if not (args.step == None or args.step == generateMasterKey):
            raise UserMessageError("The command '%s' doesn't make sense unless you also specify the temporary directory of a previous run with --temporary-directory.", args.step)
        workingDirectory = tempfile.mkdtemp(dir = "/run/shm", prefix = "gpg-key-gen")

    gpgHomeDirectory = ensureDirectoryExists(workingDirectory + "/tmp/gpg-homedir")

    if ssssIsAvailable:
        try:
            run("ssss-split -v")
            ssssIsAvailable = True
        except ShellCommandError as e:
            ssssIsAvailable = False

    #if not ssssIsAvailable:
    #    log("ssss-split is not available, shared secrets will not be generated.")

    if not os.path.exists(gpgHomeDirectory + "/gpg.conf"):
        open(gpgHomeDirectory + "/gpg.conf", "w").write("""personal-digest-preferences SHA512
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed""")

    log("Temporary directory for sensitive data will be '" + workingDirectory + "'. Make sure it's either on a volatile storage (e.g. /run/shm/ on linux), or it's deleted using 'srm' (secure-delete) once it's not needed!")

    try:
        if args.step is None:
            generateEverything(args)
        else:
            fn = globals()[args.step]
            if fn:
                fn(args)
            else:
                raise UserMessageError("Couldn't find step (python function) '%s'", args.step)
    except UserMessageError as e:
        print(sys.argv[0] + ": " + str(e))
        sys.exit(1)

except Exception as e:
    logError(e, "Error reached toplevel, exiting.")
