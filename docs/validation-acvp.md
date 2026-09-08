# NIST ACVP validation evidence

## Algorithm profile

- Algorithm: Ascon
- Mode: AEAD128
- Revision: SP800-232
- Encryption: supported
- Decryption: supported
- Payload lengths: 0..65536 bits, byte-aligned
- Associated data lengths: 0..65536 bits, byte-aligned
- Authentication tag: 128 bits
- Nonce masking: not supported

## NIST ACVP-Server

Commit:

975de31eb83d87039ec88934fdc47d8c312b892d

## Generated vector set

Vector set ID:

1001

Test groups:

- Encrypt: 60
- Decrypt: 60

Total tests:

120

Decryption results:

- Valid authentication accepted: 30
- Invalid authentication rejected: 30

## End-to-end result

NIST GenVal validation disposition:

passed

Results:

- Passed: 120
- Failed: 0

## SHA-256 evidence

registration.json

2b010f902286f4c5d9c621030e60f03081bf7975b9890ad422e7af43e91e9707

prompt.json

efb0939de64cde144f6bef7f4a51e3ee32e820be5a7dc85c96c76cad0f233c8a

expectedResults.json

d72cca05bb82da52fb92a817c6769d652fe65395eee3ae79845a22bd3d073da7

internalProjection.json

5e270af776b8f47eb9d0c1c3ccdf3ecc36f2bb955789fd093481e3010d88aa19

response.json

b6a48d8c1631fa3dca9ea7e69574fe65e99db8a7e6f969009bccf0a486b90455

validation.json

ca564c2843c647c6c11de0024b7453f1ef55064f8ba8eea12e54517083e2b4c2

## Scope

This is a local ACVP end-to-end validation using the NIST ACVP-Server
generation and validation software.

It is not a formal CAVP validation or NIST certification.
