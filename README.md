# lockbox

A cryptographic identity tool with web-of-trust, written in C.

## What it does

lockbox manages Ed25519 keypairs and uses them to encrypt, decrypt, sign, and
verify files. Identities are tracked through an append-only sigchain, and trust
is established via a web-of-trust model with key certification and identity
proofs (DNS, HTTPS, GitHub). Key discovery works over a DHT.

## Building

Requires libsodium, jansson, curl, and ncurses.

```
make
```

To install (default prefix `/usr/local`):

```
make install
```

## Usage

```
lockbox init              # generate a new keypair
lockbox fingerprint       # show your key fingerprint
lockbox export            # export your public key
lockbox import <file>     # import someone's public key
lockbox encrypt <fp> <f>  # encrypt a file to a recipient
lockbox decrypt <file>    # decrypt a file sent to you
lockbox sign <file>       # create a detached signature
lockbox verify <sig> <f>  # verify a detached signature
lockbox certify <fp>      # certify a key in your web-of-trust
lockbox prove-dns <dom>   # prove ownership of a domain via DNS
lockbox prove-https <dom> # prove ownership via HTTPS
lockbox prove-github <u>  # prove a GitHub identity
lockbox lookup <target>   # look up a key by fingerprint or proof
lockbox dht-publish       # publish your key to the DHT
lockbox dht-lookup <t>    # look up a key via DHT
lockbox tui               # interactive terminal UI
```

## License

All rights reserved.
