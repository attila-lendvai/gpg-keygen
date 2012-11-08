# gpg-keygen #

A script to generate PGP keys with GnuPG, following best practices, or at least an approximation thereof.

The aim of this document is to provide a concise and up-to-date description of best practices regarding the usage of [GnuPG](http://www.gnupg.org/). A basic understanding of [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography), and [GnuPG](http://www.gnupg.org/) in particular is assumed.

If something is not clear or you're new to PGP, then make sure to start with the [Glossary](#-glossary) below.

Alternatives to this project and/or further reading: [gpk](https://github.com/stef/gpk), [gpg-quickstart](http://www.madboa.com/geek/gpg-quickstart/), [gnupg howtos](http://www.gnupg.org/documentation/howtos.en.html), [Why use PGP?](http://superuser.com/a/16165/27578).

## Some quick insights ##

* [Public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) happens between two encryption **keys**, which is not necessarily only two humans, unless enough care has been taken when exchanging public keys and to keep the secret keys secret.
* In a digital networked world it's not possible to delete any published information, it must be assumed to be just there forever. This also applies to PGP keys.
* Properly authenticated revocation requests can be published though. If such requests are [digitally signed](http://en.wikipedia.org/wiki/Digital_signature) (authenticated), then they will be honored by programs using e.g. a PGP key (key servers, client programs), and the revoked data will be ignored/hidden accordingly.
* Having a separately stored revocation certificate in your backups comes very handy if your key gets compromised. By publishing it you can tell your peers that your key should not be used anymore.
* The most precious part of a _PGP key block_ is its _master signing key_.
* The _master signing key_ of a _PGP key block_ is rarely needed (mostly when editing the _PGP key block_ itself and when signing other people's keys, and granted that at least one additional signing subkey exists to sign ordinary documents).
* If you don't trust the software environment and/or the computer generating or using your gpg key, then you cannot trust the key and the cryptography either. [Opensource](http://en.wikipedia.org/wiki/Open-source_software) is a minimum in security, so use a Linux live cd or something similar from a trusted source to generate and/or use your master signing key, preferrably while being offline! E.g. [Tails](http://tails.boum.org/), [Privatix](http://www.mandalka.name/privatix/) or [Liberté Linux](http://dee.su/liberte).
* There are nice hardware solutions to protect your keys like [crypto-stick.com](http://www.crypto-stick.com/)
* If you forget the passphrase for your already published key, and you don't have a revocation certificate, then your key will be lingering on the keyservers confusing your peers, who will annoy you by sending you messages you can't read.
* Three to five word long sentences (based on a non-trivial vocabulary) are easier to remember than a bunch of random characters, and are [better passphrases](http://www.baekdal.com/insights/password-security-usability). You can even build a little story around them to have separate but semantically interconnected passphrases (for the keys, for the revocation certificate, etc.). A vivid dream or delightful fantasies can be a good basis... :)
* ...but at the end of the day it'll always be a tradeoff between security and convenience. Assess your risks and act accordingly.

The PGP algorithm needs an extra parameter, a key, to sign or encrypt data. That parameter is a cryptographic keypair, usually one of the subkeys from a PGP key block. New subkeys can be freely generated and published, so [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy) can be achieved by publishing new subkeys, as long as the secret part of the master signing keypair has not been compromised. Therefore the most precious part of a PGP key block is its master signing key, because whenever new information is attached to the key block (e.g. a new _subkey_ is generated), this new data must be signed by the secret part of the master signing keypair, otherwise conforming programs will reject the new unsigned or improperly signed part of the PGP key block. This way only that person can publish valid additions to the key block who controls the secret part of the master signing key.

So, in short: keep the secret part of your master signing key safe!

## Generating a key ##

The aim is to generate a digital identity that can serve to identify you and to facilitate secret communication with you in the future.

Things to consider:

* Having a strong master signing key can provide a longer time span for your digital identity and for [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy)
* Longer signing keys generate longer signatures.
* With a valid signing subkey, the master signing key is rarely used, so the size of the signatures it generates is not too important.
* It's possible to generate 8192 bit RSA signing keys (as of this writing, by editing the GnuPG sources to overcome the 4096 bit user interface limit, or as this script does, by using batch mode).
* Some GnuPG configuration parameters affect newly generated keys (although not in a permanent way). See _setperf_ to set the preferred hash algorithms for identities e.g. [here](https://wiki.ubuntu.com/SecurityTeam/GPGMigration).

Some more thoughts [here](http://www.ctrlc.hu/~stef/blog/posts/PGP_key_generation.html).

## Using PGP without keeping the secret part of your master signing key on your computer ##

GnuPG has no problem working with a PGP key block that is missing the secret part of its master signing key, as long as it's not needed for an operation. Therefore it's a good idea not to store the secret part of the master signing key in the regularly used gpg home directory, but rather keep it at a safer location.

This script generates:

* a master signing key
* a subkey for signing
* a subkey for encryption
* export the secret part of the master signing key into the file <code>secret-master-key.gpg</code>
* export the secret parts of the two generated subkeys into the file <code>secret-subkeys.gpg</code>
* export the public parts of all the three generated keys into the file <code>public-keys.gpg</code>
* generate and symmetrically encrypt a revocation certificate into the file <code>revocation-certificate-for-[keyid]-passphrase-protected.gpg</code>
* (planned: support for [<code>ssss-split</code>](http://point-at-infinity.org/ssss/) to generate [secret sharing](http://en.wikipedia.org/wiki/Secret_sharing) to backup the master key and the revocation certificate in a distributed manner)

Once the files have been generated you can import them into gpg homedir's (the default one is <code>~/.gnupg</code>). One should be on your regularly used computer(s), but it should only hold the secret parts of the subkeys and the public parts of all the keys (but not the secret part of the master signing key, which should be handled with more precautions):

        $ gpg --import secret-subkeys.gpg public-keys.gpg
        $ gpg --list-secret-keys
        ---------------------------------
        sec#  8192R/ABCD1234 2010-01-01
        uid                  John Doe <john.doe@example.com>
        ssb   4096R/42AA42AA 2010-01-01 [expires: 2015-01-01]
        ssb   2048R/41BB41BB 2010-01-01 [expires: 2015-01-01]

(the '#' character in the output shows that the secret part of the master signing key is missing)

## <a id="-glossary"></a> Glossary ##

* _PGP key_ - It's usually a shorthand for _PGP key block_, which will be the case in this document, too. Not to be confused with _asymmetric cryptographic keypairs_, which are merely parts of _PGP key blocks_.
* _PGP key block_ - a complex structure of information, including but not limited to the following: multiple cryptographic keys, multiple identities (email addresses, photos, etc), digital signatures on various parts of the key block potentially made using other people's keys (e.g. signing someone's key to communicate your belief to the world that the identities listed in the given PGP key, and the secret part of said PGP key belong to the same (real world) person), etc...
* _subkey_ - _PGP key blocks_ can have, among other things, 1+ _asymmetric cryptographic keypairs_. One such _asymmetric cryptographic keypair_ is mandatory for normal operation. It's called the _master signing key_, and it's used to sign various information inside the key block, e.g. identities and/or other cryptographic keys, which are called _subkey_s.
* _asymmetric cryptographic keypair_ - they are basically pairs of very big interconnected random numbers, one of them should be made public, while the other one should be kept secret. Asymmetric encryption algorithms use the public part to encrypt data and to verify signature blocks, while use the secret part to decrypt data and to generate signature blocks.
