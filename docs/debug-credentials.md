# LPC55 Debug Credential Certificates

We use the LPC55S69 as our root of trust (RoT).
We manufacture systems such that access to the debug facilities in the RoT requires authentication.
Debug auth credential certificates (DCs) must be signed by one of the roots / trust anchors configured for a given platform.

DCs aren't really certificates in the traditional x.509 / RFD 5280 sense.
Instead they're a binary structure specific to the NXP implementation and described in §51.7 of the LPC55S6x User Manual (aka UM11126) Rev 1.8.
DCs cannot be signed by an intermediate in the same PKI, only the root.
Like the verified boot implementation on the LPC55S69, DCs are limited to RSA keys.

## Producing DCs

The offline key store manages our root signing keys and since DCs must be signed by one of the roots, OKS must perform the signing.
To provide OKS with the data / input required to sign a DC we define a structure that we call a DC signing request specification (DcsrSpec).

At the top level the DcsrSpec includes:
- a debug credential signing request (DCSR)
- the label of the key managed by OKS that will sign the output DC
- the labels of the keys (always 4 for production systems) managed by OKS that have been programmed into the RoT

When processing a DcsrSpec OKS will use the labels that identify the trust anchors in the RoT to collect their certificates from the OKS CA metadata.
OKS then gets the public key for the signer from this collection of certs.
If this collection of certs does not contain the signer then OKS will reject the DcsrSpec as invalid.
The public key for the signer, the collection of trust anchors, and the DCSR are then used to create the DC structure that is signed by the key in OKS.
The output is the signed DC.

Most of the hard work in this process is done by the [lpc55_support](https://github.com/oxidecomputer/lpc55_support) crate.

## Issuance Policy

RFD 5280 defines policies that certificate authorities implement and abide by (at least that's what they're supposed to do).
DCs do not come with such requirements but we do put some restrictions on their issuance.
OKS is our policy enforcement point by virtue of hosting the trust anchors that must sign the DCs.

### One key, one DC

If we're willing to issue more than one DC for a given key we create a situation where we must trust the key holder to use the right DC in the right context.
One could then attack the key holder by confusing them into using a key in the wrong context.
If the number of DCs we may issue is reasonably bounded (under some threshold) we can mitigate this threat by issuing only one DC per signing key.
For now we're below this threshold and assume that will remain a constant.

Implementing this policy when OKS is presented with a DC to sign requires that we compare the public key from the request (DcsrSpec) to each previously issued DC.
We don't need to be able to do this particularly quickly so setting up and maintaining a database that we can query is overkill.
Instead we can use the file system much like the `openssl ca` command.

Reading back all past DCs from the file system could get expensive over time.
To avoid this we need an identifier that we can put into the DC file names such that we can enforce this policy by reading the directory entry.
We can't put the full 4k RSA public key in the file name so we assign each a name that is the hex encoded sha256 digest.
We've been using the suffix `dc.bin` when exporting signed DCs and so we'll append it to these file names as well.

Before OKS signs a DC it calculates the digest of the public key and searches through the collection of previously issued DC files looking for one that begins with the same digest.
If a match is found OKS will load this DC, verify the signature over it, then calculate the digest of the public key inside manually to verify.

### Digest What

When calculating the digest of the public key from a DC we need to be explicit about the bytes we're running through the hash function.
The `DebugCredentialSigningRequest` structure from the `lpc55_support` crate provides the RSA key as the modulus and exponent concatenated.
Unfortunately this format isn't understood by tools like `openssl`.

While we'll be generating these digests in OKS, we want to enable external verification.
Doing this verification requires generating these digests from public keys obtained elsewhere and likely in other (standardized) formats.
These formats are going to either be PKCS#1, or SPKI.

Both of these formats store the public key as a DER encoded structure.
The prior is specific to RSA public keys and so we can hash this structure in its DER form directly:

```shell
openssl rsa -pubin -in path-to-pkcs1.pem -outform DER -RSAPublicKey_out | sha256sum
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  -
```

SPKI is conveniently compatible with PKCS#1 in that SPKI prepends an algorithm identifier  on to the PKCS#1 DER encoded key.
This allows us to reconstruct our digest from the SPKI encoded key by dropping the first 24 bytes from its DER encoding:

```shell
openssl rsa -pubin -in path-to-spki.pem -outform DER | tail --bytes=+25 | sha256sum
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  -
```
