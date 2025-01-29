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
