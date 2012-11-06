# gpg-keygen #

A script to generate PGP keys with GnuPG, following best practices, or at least an approximation thereof.

# The best practices #

The aim of this document is to provide concise and up-to-date best practices regarding the usage of [GnuPG](http://www.gnupg.org/). A basic understanding of [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography), and [GnuPG](http://www.gnupg.org/) in particular is assumed.

If something is not clear, make sure to check the [Glossary](#glossary) below.

## Some quick insights ##

* You cannot delete any change you have made to a PGP key once it has been published. What you can do though is to publish revocation requests digitally signed by your secret key and hope that programs (e.g. key servers, client programs) will honour your request to drop and/or ignore the revoked data.
* The most precious part of a _PGP key block_ is its _master signing key_.
* The _master signing key_ of a _PGP key block_ is rarely used (mostly when editing the _PGP key block_ itself, and granted that at least one additional signing subkey has been generated to sign ordinary documents (which is a good idea)).

The PGP algorithm needs an extra parameter (a key) to sign or encrypt some data. That parameter is a cryptographic keypair, usually one of the subkeys from a PGP key block. New subkeys can be freely generated and published, so [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy) can be achieved by publishing new subkeys if the secret part of the master signing keypair has not been compromised. Therfore the most precious part of a PGP key block is its master signing key, because whenever new information is attached to the key block (e.g. a new _subkey_ is generated), this new data must be signed by the secret part of the master signing keypair, otherwise conforming programs will reject the new unsigned or improperly signed part of the PGP key block. This way only that person can publish valid additions to the key block who controls the secret part of the master signing key.

## Using PGP without keeping the secret part of your master signing key on your computer ##

GnuPG has no problem working with a PGP key that is missing the secret part of its master signing key as long as it's not needed for an operation. Therefore it's a good idea to delete the secret part of the master signing key from the regularly used copy of a PGP key block, and keep a copy of the intact key block at a safer, offline location.

This script generates:

* a master signing key
* a subkey for signing
* a subkey for encryption
* an export of the secret part of the master signing key into the file 'secret-master-key.gpg'
* an export of the secret parts of the subkeys into the file 'secret-subkeys.gpg'
* an export of the public parts of all the three generated keys into the file 'public-keys.gpg'
* a symmetrically encrypted revocation certificate into the file 'revocation-certificate-for-[keyid]-passphrase-protected.gpg'
* (planned: support for ssss-split to generate [secret sharing](http://en.wikipedia.org/wiki/Secret_sharing) to backup the master key and the revocation certificate in a distributed manner)

Once the files have been generated you can import them into two gpg homedir's, one should be on your main device(s) and should only hold the secret parts of the subkeys and the public parts of all the keys:

        $ gpg --import secret-subkeys.gpg public-keys.gpg
        $ gpg --list-secret-keys
        ---------------------------------
        sec#  8192R/ABCD1234 2010-01-01
        uid                  John Doe <john.doe@example.com>
        ssb   4096R/42AA42AA 2010-01-01 [expires: 2015-01-01]
        ssb   2048R/41BB41BB 2010-01-01 [expires: 2015-01-01]

(the '#' character in the output shows that the secret part of the master signing key is missing)

## Generating a key ##

The aim is to generate a digital identity that can serve to identify you and to facilitate secret communication with you in the future.

Things to consider:

* Having a strong master signing key can provide a longer timespan for your digital identity and for [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy)
* If you have a valid signing subkey, then the master signing key is rarely used, so the size of the signatures it generates is not too important (bigger keys generate bigger signature blocks).
* It's possible to generate 8192 bit RSA keys (as of this writing, by editing the GnuPG sources to overcome the 4096 bit user interface limit, or by using batch mode, as used by this script).
* Certain GnuPG configurations in effect when generating a new key will affect the new key (although not in a permanent way). See _setperf_ to set the preferred hash algorithms for identities e.g. [here](https://wiki.ubuntu.com/SecurityTeam/GPGMigration).

Some more thoughts [here](http://www.ctrlc.hu/~stef/blog/posts/PGP_key_generation.html).

## <a id="glossary"></a> Glossary ##

* _PGP key_ - It's usually a shorthand for _PGP key block_, which will be the case in this document, too. Not to be confused with _asymmetric cryptographic keypairs_, which are merely parts of _PGP key blocks_.
* _PGP key block_ - a complex structure of information, including but not limited to the following: multiple cryptographic keys, multiple identities (email addresses, photos, etc), digital signatures on various parts of the key block potentially made using other people's keys (e.g. signing someone's key to communicate your belief to the world that the identities listed in the given PGP key, and the secret part of said PGP key belong to the same (real world) person), etc...
* _subkey_ - _PGP key block_s can have, among other things, 1+ _asymmetric cryptographic keypairs_. One such _asymmetric cryptographic keypair_ is mandatory for normal operation. It's called the _master signing key_, and it's used to sign various information inside the key block, e.g. identities and/or other cryptographic keys, which are called _subkey_s.
* _asymmetric cryptographic keypair_ - they are basically pairs of very big interconnected random numbers, one of them should be made public, while the other one should be kept secret. Asymmetric encryption algorithms use the public part to encrypt data and to verify signature blocks, while use the secret part to decrypt data and to generate signature blocks.
