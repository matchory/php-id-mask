IDMask
======
> IDMask is an implementation of [IDMask](https://github.com/patrickfav/id-mask) in PHP.

IDMask is a PHP library for masking **internal IDs** (e.g. from your DB) when they need to be publicly published to
**hide their actual value and to prevent forging**. This should make it very hard for an attacker to **understand**
provided IDs (e.g. by witnessing a sequence, deducting how many orders you had, etc.) and **prevent guessing** of
possible valid ones. Masking is **fully reversible** and also supports optional **randomization** for e.g.
**shareable links** or **one-time tokens**.  
It has a wide support for various **data types** including (big) integers, UUIDs and arbitrary strings. This library
bases its security on **strong cryptographic primitives** ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard),
[HMAC](https://en.wikipedia.org/wiki/HMAC), [HKDF](https://en.wikipedia.org/wiki/HKDF)) to create a secure encryption
schema. It was inspired by [HashIds](https://hashids.org/), but tries to tackle most of its shortcomings.

## Feature Overview

- **Secure**: Creates encrypted IDs with **proper cryptography** ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard),
  [HKDF](https://en.wikipedia.org/wiki/HKDF)) including **forgery protection** ([HMAC](https://en.wikipedia.org/wiki/HMAC))
- **Wide range of data types supported**: Masks IDs from integers, UUIDs, strings, or byte sequences
- **Full support of types**: Has no arbitrary restrictions like "only positive numbers", etc.
- **ID randomization**: If enabled, IDs are generated which appear uncorrelated with the same underlying value.
- **No collisions possible**: As IDs are not hashed or otherwise compressed, collisions are impossible.
- **Lightweight & Easy-to-use**: Has only minimal dependencies and a straight forward API.
- **Supports multiple encodings**: Depending on your requirement (short IDs vs. readability vs. should not contain
  words) multiple encodings are available including [Base64](https://en.wikipedia.org/wiki/Base64),
  [Base32](https://en.wikipedia.org/wiki/Base32) and [Hex](https://en.wikipedia.org/wiki/Hexadecimal) with the option of
  providing a custom one.

<!-- - **Built-in caching support**: To increase performance a PSR-6 cache implementation can be used. -->
<!-- - **Framework integrations included**: Includes support for Laravel and Symfony out of the box -->

Installation
------------
Install IDMask from Composer:

```bash
composer require matchory/id-mask
```

Quickstart
----------

```php
use Matchory\IdMask\IdMask;
use Matchory\IdMask\KeyManagement\KeyStore;
use Matchory\IdMask\KeyManagement\SecretKey;

$keyStore = KeyStore::with(SecretKey::generate())
$mask = IdMask::forInteger($keyStore)->mask('foo');

assert('foo' === IdMask::forInteger($keyStore)->unmask($mask))
```

TODO: More content will be available as the library gets fully implemented.

Further Reading
---------------

### Main Article

- [A Better Way to Protect Your IDs](https://medium.com/@patrickfav/a-better-way-to-protect-your-database-ids-a33fa9867552)

### Discussions

- [Exposing database IDs - security risk?](https://stackoverflow.com/questions/396164/exposing-database-ids-security-risk)
- [Prevent Business Intelligence Leaks by Using UUIDs Instead of Database IDs on URLs and in APIs](https://medium.com/lightrail/prevent-business-intelligence-leaks-by-using-uuids-instead-of-database-ids-on-urls-and-in-apis-17f15669fd2e)
- [Why not expose a primary key](https://softwareengineering.stackexchange.com/questions/218306/why-not-expose-a-primary-key)
- [Sharding & IDs at Instagram](https://instagram-engineering.com/sharding-ids-at-instagram-1cf5a71e5a5c)
- [HashId Cryptanalysis](https://carnage.github.io/2015/08/cryptanalysis-of-hashids)
- [Discussion about IDMask encryption schema](https://crypto.stackexchange.com/q/68415/44838)

### Similar Libraries

- [HashIds](https://github.com/10cella/hashids-java)
- [NanoId](https://github.com/ai/nanoid)

Contributing
------------
Submit a pull request or open an issue on GitHub. We welcome contributions from all kinds of people!
