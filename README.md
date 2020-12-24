# gpg-keygen #

A readme and a script to generate [PGP](http://en.wikipedia.org/wiki/Pretty_Good_Privacy) keys using [GnuPG](http://www.gnupg.org/), using the current best practices.

Its goal is to provide a concise and up-to-date description of best practices regarding the usage of GnuPG. A basic understanding of [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography), and GnuPG in particular is assumed.

If something is not clear or you're new to PGP, then make sure to start with the [Glossary](#-glossary) below.

## Status as of 2021 ##

By now this has become a bit obsolete. We now have specialized devices like Trezor for our keys, and new projects are inching towards superseding the entire PGP framework.

**The rest is from around 2016.**

## Some quick insights ##

* [Public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) happens between two encryption **keys**, which is not necessarily only two humans, unless enough care has been taken when exchanging public keys and to keep the secret keys indeed secret.
* In a digital networked world it's not possible to delete any published information, it must be assumed to be just there forever. This also applies to PGP keys.
* Properly authenticated revocation requests can be published, though. If such requests are [digitally signed](http://en.wikipedia.org/wiki/Digital_signature) (authenticated), then they will be honored by programs handling e.g. PGP keys (key servers, client programs), and the revoked data will be ignored/hidden from the user accordingly.
* Having a separately stored revocation certificate in your backup comes very handy if your key gets compromised or lost. By publishing it you can tell your peers that your key should not be used anymore.
* The most precious part of a _PGP key block_ is its _master signing key_.
* The _master signing key_ of a _PGP key block_ is rarely needed (mostly when editing/extending the _PGP key block_ itself and when signing other people's keys).
* You can only trust you generated PGP key to the extent you trust the software environment and/or the computer generating it. [Opensource](http://en.wikipedia.org/wiki/Open-source_software) is a minimum in security, so use a Linux live cd or something similar from a trusted source to generate and/or use your master signing key, preferably while being offline (see _live CD_'s in the [Glossary](#-glossary))!
* Specialized hardware solutions offer much better protection for secret keys. See [below](#-hardware).
* If you forget the passphrase for your already published key, and you don't have a revocation certificate either, then your key will be lingering on the keyservers confusing your peers, who will annoy you by sending you messages you cannot read.
* Passphrases: three to five word long sentences that you make up yourself (based on a non-trivial vocabulary, personal experiences, dreams, preferably with s0me typ0s) are easier to remember than a bunch of random characters, and are [better passphrases](http://www.baekdal.com/insights/password-security-usability). You can even build a little story around them to have separate but semantically interconnected passphrases (for the keys, for the revocation certificate, etc.). A vivid dream or delightful fantasies can be a good basis for something you won't forget... :)
* ...but at the end of the day it'll always be a tradeoff between security and convenience. Assess your risks and act accordingly.

The PGP algorithm needs an extra parameter, a key, to sign or encrypt data. That parameter is a cryptographic keypair, usually one of the subkeys from a PGP key block. New subkeys can be freely generated and published, so [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy) can be achieved by publishing new subkeys, as long as the secret part of the master signing keypair has not been compromised. Therefore the most precious part of a PGP key block is its master signing key, because whenever new information is attached to the key block (e.g. a new _subkey_ is generated), this new data must be signed by the secret part of the master signing keypair, otherwise conforming programs will reject the new unsigned or improperly signed part of the PGP key block. In this scheme publishing valid additions to the key block is only possible by people who know the secret part of the master signing key. This is ideally you, and you only.

So, to conclude: keep the secret part of your master signing key safe!

## Generating a key ##

The aim is to generate a digital identity that can serve to identify you and to facilitate secret communication with you in the future.

Things to consider:

* If a valid signing subkey exists, then the master signing key is rarely used (only to sign internal parts of the key block itself, when explicitly selected, or when signing other people's keys), so the size of the signatures it generates is not a major concern.
* Having a strong master signing key (and taking good care of it) can provide a long time span for your digital identity (possibly 10+ years) and for [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy).
* The security of RSA keys does not scale well beyond 2048 bits, use [ECC](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography) (Elliptic curve cryptography) instead [as recommended](https://gnupg.org/faq/gnupg-faq.html#please_use_ecc). Unfortunately it requires GnuPG 2.1+ (2014 Nov).
* Longer signing keys generate longer signatures.
* Signature length: RSA > DSA = [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (Elliptic Curve DSA) (but [there's more to this story](http://superuser.com/questions/13164/what-is-better-for-gpg-keys-rsa-or-dsa)).
* Some GnuPG configuration parameters affect newly generated keys (although not in a permanent way); e.g. see _setpref_ to set the preferred hash algorithms for identities [here](https://wiki.ubuntu.com/SecurityTeam/GPGMigration).

Even more thoughts [here](http://www.ctrlc.hu/~stef/blog/posts/PGP_key_generation.html).

## Using GnuPG ##

GnuPG properly operates with a PGP key block that is missing the secret part of its master signing key, as long as it's not needed for an operation. Therefore it's a good idea not to store the secret part of the master signing key in the regularly used gpg home directory, but rather generate and handle it in a safer environment; e.g. generate and handle it using a [live CD](#-livecd) without Internet connection, and store it on a pendrive dedicated to this purpose. Then only attach it when needed (e.g. when signing other people's keys or when your own keyblock needs to be modified).

This script generates (with defaults in parens):

* a master signing key (RSA 4096 bit, no expiration date marked)
* a subkey for signing (RSA 4096 bit, 3 years)
* a subkey for encryption (RSA 2048 bit, 3 years)
* export the secret part of the master signing key into the file <code>secret-master-key.gpg</code>
* export the secret parts of the two generated subkeys into the file <code>secret-subkeys.gpg</code>
* export the public parts of all the three generated keys into the file <code>public-keys.gpg</code>
* generate and symmetrically encrypt a revocation certificate into the file <code>revocation-certificate-for-[keyid]-passphrase-protected.gpg</code>
* (planned: support for [<code>ssss-split</code>](http://point-at-infinity.org/ssss/) to generate [secret sharing](http://en.wikipedia.org/wiki/Secret_sharing) to backup the master key and the revocation certificate in a distributed manner)

Once the exported files have been generated, you can import them into the gpg homedir's on your devices (by default <code>~/.gnupg</code>). Where you should import and what depends on the level of security you want to achieve, but keeping the master key offline is advised as described above.

        $ gpg --import secret-subkeys.gpg public-keys.gpg
        $ gpg --list-secret-keys
        ---------------------------------
        sec#  4096R/ABCD1234 2010-01-01
        uid                  John Doe <john.doe@example.com>
        ssb   4096R/42AA42AA 2010-01-01 [expires: 2013-01-01]
        ssb   2048R/41BB41BB 2010-01-01 [expires: 2013-01-01]

(the '#' character in the output shows that the secret part of the master signing key is missing)

## <a id="-hardware"></a> SmartCards and other hardware keys ##

SmartCards and USB cryptographic tokens are specialized simple computers that perform cryptographic operations. They are designed to keep the secret keys secret even against physical attacks. They are much more secure than storing a key on a personal computer, but they are not flawless [⁽¹⁾](http://smartfacts.cr.yp.to/) [⁽²⁾](http://www.cl.cam.ac.uk/~sjm217/papers/). Usually they can store three separate keys for signing, encryption, and authentication. The secret keys can be either uploaded or generated on the cards themselves, so that they never get exposed to less secure environments.

* [The OpenPGP Card version 2.0](http://www.g10code.de/p-card.html) - a SmartCard with [extensive documentation](http://www.g10code.de/docs/openpgp-card-2.0.pdf) and thus stable Linux support. You can also get one by [joining the FSFE Fellowship](http://www.fsfe.org/join). Supports three 4096 bit keys and on-card key generation[⁽¹⁾](http://shop.kernelconcepts.de/product_info.php?cPath=1_26&products_id=42).
* [Crypto Stick](http://www.crypto-stick.com/) - a tiny OpenSource USB computer and firmware with an integrated proprietary smart card chip. Supports _OATH TOTP_ as [described here](https://www.crypto-stick.com/2012/OATH-One-Time-Passwords-Allow-Login-to-Gmail-Dropbox-AWS).
* [gnuk](http://www.fsij.org/gnuk/) - a portable OpenSource implementation of the OpenPGP Card specification that can run on e.g. [this](http://www.seeedstudio.com/wiki/FST-01) tiny ARM based OpenSource USB computer.

Some laptops have internal smart card readers, and higher security external readers have their own PIN entry keyboard.

Further information on using smart cards on Linux: [Debian wiki](https://wiki.debian.org/Smartcards), [Using an OpenPGP SmartCard](http://www.narf.ssji.net/~shtrom/wiki/tips/openpgpsmartcard), [OpenSC – tools and libraries for smart cards](https://github.com/OpenSC/OpenSC/wiki), [GnuPG wiki](http://wiki.gnupg.org/).

## <a id="-glossary"></a> Glossary ##

* _PGP key_ - It's usually a shorthand for _PGP key block_, which will be the case in this document, too. Not to be confused with _asymmetric cryptographic keypairs_, which are merely parts of _PGP key blocks_.
* _PGP key block_ - a complex structure of information (normally stored in ~/.gnupg/). Examples of the information it can contain: multiple cryptographic (sub)keys; multiple identities (email addresses, photgraphs, etc); digital signatures on various parts of the key block (potentially made by other people's keys, e.g. to communicate the belief to the rest of the world that the same real world person owns the listed digital identities, and also the secret part of the key).
* _subkey_ - _PGP key blocks_ can have, among other things, multiple _asymmetric cryptographic keypairs_. One such _asymmetric cryptographic keypair_ is mandatory for normal operation. It's called the _master signing key_, and it's used to sign various information inside the key block, e.g. identities and/or other cryptographic keys, which are called _subkeys_.
* _asymmetric cryptographic keypair_ - they are basically pairs of very big interconnected random numbers, one of them should be made public, while the other one should be kept secret. Asymmetric encryption algorithms use the public part to encrypt data and to verify signature blocks, while use the secret part to decrypt data and to generate signature blocks.
* [OATH](http://www.openauthentication.org/aboutOath) is short for Initiative for Open Authentication. Among other things it defines a [Time-based One-time Password (TOTP)](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) authentication standard, supported by [more and more websites](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm#Public_Server_Implementations).
* Live CD is a bootable read-only operating system, like these security focused Linux Live CDs (bootable from USB pendrives also):
  * [Tails](http://tails.boum.org/)
  * [Privatix](http://www.mandalka.name/privatix/)
  * [Liberté Linux](http://dee.su/liberte).

## Alternatives and/or further reading ##

* [gpk](https://github.com/stef/gpk)
* [gpg-quickstart](http://www.madboa.com/geek/gpg-quickstart/)
* [gnupg howtos](http://www.gnupg.org/documentation/howtos.en.html)
* [Why use PGP?](http://superuser.com/a/16165/27578)

## Credits ##

Written by Attila Lendvai <attila@lendvai.name> (Key fingerprint: 2FA1 A9DC 9C1E BA25 A59C  963F 5D5F 45C7 DFCD 0A39).
