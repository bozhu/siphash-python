# siphash-python

A Python implementation of [SipHash](https://131002.net/siphash/).

The source code is under MIT license.

## Usage

Import as a class:

    >>> from siphash import SipHash
    >>> my_hash = SipHash()

Or use specific `c` and `d`:

    >>> my_hash = SipHash(c=2, d=4)

Use a 128-bit key to authenticate a string:

    >>> k = 0x0f0e0d0c0b0a09080706050403020100
    >>> m = 'A short message'
    >>> t = my_hash.auth(k, m)
    >>> hex(t)
    '0xae43dfaed1ab1c00L'
