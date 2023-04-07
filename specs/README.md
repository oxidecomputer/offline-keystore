This directory contains spec files that define the root keys for the 2 offline
roots (staging / production) for our 3 PKIs (one for each platform: Gimlet,
Sidecar & PSC). For development or testing purposes we recommend using the spec
files in the 'data' directory in the root of the projects git repo. The spec
files here define RSA keys and those are very slow to generate on the YubiHSM2.
