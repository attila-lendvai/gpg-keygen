# gpg-keygen #

Generate PGP keys with GnuPG, following best practices.

The rest of this document is a preliminary version of what aims to be a very high signal to noise ratio document on the usage of GnuPG.

# GPG best practices #

The aim of this document is to provide up-to-date best practices regarding the usage of [GnuPG](http://www.gnupg.org/). A basic understanding of [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography), and [GnuPG](http://www.gnupg.org/) in particular is assumed.

If something is not clear, make sure to check the [Glossary][] below.

## Some quick insights ##

* You cannot delete any change you have made to a PGP key once it has been published. What you can do though is to publish revocation requests digitally signed by your secret key and hope that programs (e.g. key servers, client programs) will honour your request to drop and/or ignore the revoked data.
* The most precious part of a _PGP key block_ is its _main signing key_.
* The _main signing key_ of a _PGP key block_ is rarely used (mostly when editing the _PGP key block_ itself, and granted that at least one additional signing subkey has been generated to sign ordinary documents, which is a good idea).

The PGP algorithm needs an extra parameter (a key) to sign or encrypt some data. That parameter is a cryptographic keypair, usually one of the subkeys from a PGP key block. New subkeys can be freely generated and published, so [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy) can be achieved by publishing new subkeys if the secret part of the main signing keypair has not been compromised. Therfore the most precious part of a PGP key block is its main signing key, because whenever new information is attached to the key block (e.g. a new _subkey_ is generated), this new data must be signed by the secret part of the main signing keypair, otherwise conforming programs will reject the new unsigned or improperly signed part of the PGP key block. This way only that person can publish valid additions to the key block who controls the secret part of the main signing key.

## Using PGP without keeping the secret part of your main signing key on your computer ##

GnuPG has no problem working with a PGP key that is missing the secret part of its main signing key as long as it's not needed for an operation. Therefore it's a good idea to delete the secret part of the main signing key from the regularly used copy of a PGP key block, and keep a copy of the intact key block at a safer, offline location.

1. Make sure you already have at least one valid signing subkey. This can be done later also, but it's easier while you still have the secret part of the main signing key in the PGP key block.
2. Make a file level backup of your ~/.gnupg/. **This is NOT optional**, this backup will be needed whenever you will want to edit your key, or you want to do any other operation that requires the secret part of your main signing key.
3. Then do the following somewhere safe, where no one else can read the filesystem:

        $ gpg --export-secret-subkeys ABCD1234 >secret-subkeys.txt
        $ gpg --delete-secret-keys ABCD1234
        $ gpg --import secret-subkeys.txt
        $ rm secret-subkeys.txt
        $ gpg --list-secret-keys
        ---------------------------------
        sec#  4096R/ABCD1234 2010-01-01
        uid                  John Doe <john.doe@example.com>
        ssb   4096R/42AA42AA 2010-01-01 [expires: 2015-01-01]
        ssb   2048R/41BB41BB 2010-01-01 [expires: 2015-01-01]

(the '#' character in the output shows that the secret part of the main signing key is missing)

## Generating a new key ##

The aim is to generate a digital identity that can serve to identify you and to facilitate secret communication with you in the future.

Things to consider:

* Having a strong main signing key can provide a longer timespan for your digital identity and for [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy)
* If you have a valid signing subkey, then the main signing key is rarely used, so the size of the signatures it generates is not too important (bigger keys generate bigger signature blocks).
* It's possible to generate 8192 bit RSA keys by editing the GnuPG sources and recompiling it (the current hardcoded limit is 4096 bits). Hopefully this will get simpler in the future.
* Certain GnuPG configurations in effect when generating a new key will affect the new key (although not in a permanent way). See _setperf_ to set the preferred hash algorithms for identities e.g. [here](https://wiki.ubuntu.com/SecurityTeam/GPGMigration).

Some more thoughts [here](http://www.ctrlc.hu/~stef/blog/posts/PGP_key_generation.html).

## Glossary ##

* _PGP key_ - It's usually a shorthand for _PGP key block_, which will be the case in this document, too. Not to be confused with _asymmetric cryptographic keypairs_, which are merely parts of _PGP key blocks_.
* _PGP key block_ - a complex structure of information, including but not limited to the following: multiple cryptographic keys, multiple identities (email addresses, photos, etc), digital signatures on various parts of the key block potentially made using other people's keys (e.g. signing someone's key to communicate your belief to the world that the identities listed in the given PGP key, and the secret part of said PGP key belong to the same (real world) person), etc...
* _subkey_ - _PGP key block_s can have, among other things, 1+ _asymmetric cryptographic keypairs_. One such _asymmetric cryptographic keypair_ is mandatory for normal operation. It's called the _main signing key_, and it's used to sign various information inside the key block, e.g. identities and/or other cryptographic keys, which are called _subkey_s.
* _asymmetric cryptographic keypair_ - they are basically pairs of very big interconnected random numbers, one of them should be made public, while the other one should be kept secret. Asymmetric encryption algorithms use the public part to encrypt data and to verify signature blocks, while use the secret part to decrypt data and to generate signature blocks.
