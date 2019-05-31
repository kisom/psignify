psignify
========

This is a portable implementation of OpenBSD's signify[1]. Right now,
it supports generating and verifying detached signatures and keypair
generation.

There is initial support for nacl/box encryption using the libsodium
Ed25519 -> Curve25519 keypair conversion[2]. There isn't a mechanism
now for encrypting while I figure out a good format for this.


[1] https://man.openbsd.org/OpenBSD-current/man1/signify.1
[2] https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/keypair.c#L45
