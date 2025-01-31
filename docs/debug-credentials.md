# LPC55 Debug Auth Credentials

We use the LPC55S69 as our root of trust (RoT).
We manufacture systems such that access to the debug facilities in the RoT requires authentication.
This feature is described in §51.7 of the LPC55S6x User Manual (aka UM11126) Rev 1.8.

Debug auth credentials (DACs) must be signed by one of the roots / trust anchors configured for a given platform.
DACs cannot be signed by an intermediate in the same PKI, only the root.
Like the verified boot implementation on the LPC55S69, DACs are limited to RSA keys.
DACs are not certificates, they are a binary structure specific to the NXP implementation.

## Producing DACs

The offline key store manages our root signing keys and since DACs must be signed by one of the roots, OKS must perform the signing.
To provide OKS with the data / input required to sign a DAC we define a structure that we call a DAC signing request specification (DcsrSpec).

At the top level the DcsrSpec includes:
- a debug credential signing request (DCSR)
- the label of the key managed by OKS that will sign the output DAC
- the labels of the keys (always 4 for production systems) managed by OKS that have been programmed into the RoT

When processing a DcsrSpec OKS will use the labels that identify the trust anchors in the RoT to collect their certificates from the OKS CA metadata.
OKS then gets the public key for the signer from this collection of certs.
If this collection of certs does not contain the signer then OKS will reject the DcsrSpec as invalid.
The public key for the signer, the collection of trust anchors, and the DCSR are then used to create a binary structure that is signed by the key managed by OKS.
The output is the DAC.

Most of the hard work in this process is done by the [lpc55_support](https://github.com/oxidecomputer/lpc55_support) crate.

## Issuance Policy

RFD 5280 defines policies that certificate authorities implement and abide by (at least that's what they're supposed to do).
DACs do not come with such guidelines but we do want to put some restrictions on their issuance.
OKS is the policy enforcement point by virtue of hosting the trust anchors that must sign the DAC.

### One key, one DAC

If we're willing to issue more than one DAC for a given key we create a situation where we must trust the key holder.
We would be trusting them to use each DAC in the appropriate context.
One could then attack the key holder by attempting to confuse them into using the key in the wrong context.
If the number of DACs we may issue is reasonably bounded (under some threshold) we can mitigate this threat by issuing only one DAC per signing key.
For now we're below this threshold and assume that will remain a constant.

Implementing this policy when OKS is presented with a DAC to sign requires that we compare the public key from the request (DcsrSpec) to each previously issued DAC.
This requires we iterate over all previously issued DACs.
We don't need to be able to do this particularly quickly so setting up and maintaining a database that we can query is overkill.
Instead we can use the file system much like the `openssl ca` command.

Reading back all past DACs from the file system could get expensive over time.
To avoid this we need an identifier that we can put into the DAC file names such that we can enforce this policy by reading a directory entry.
We can't put the full 4k RSA public key in the file name so we assign each a name that is the hex encoded sha256 digest.
We've been using the suffix `dc.bin` when exporting signed DACs and so we'll use that in this case as well.

Before OKS signs a DAC it calculates the digest of the public key and then searches through the collection of previosly issued DAC files looking for a file name that begins with the same digest.
If a match is found OKS will load this DAC and calculate the digest of the public key inside manually to verify.

### Digest What

When calculating the digest of the public key from a DAC we need to be explicit about the bytes we're running through the hash function.
For as long as we're using the LPC55 for our RoT these keys will always be RSA keys.
The `DebugCredentialSigningRequest` structure from the `lpc55_support` crate packages the public key in a format specific to RSA.
RSA keys are just two integers so we could run them both through the digest `update` function effectively concatenating them into a single digest.

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
