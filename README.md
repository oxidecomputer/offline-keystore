This repo implements the parts of [yubihsm-setup](https://github.com/Yubico/yubihsm-setup) that we need for our initial key ceremony.
This work began after a few things became apparent:

* the [YubiHSM](https://www.yubico.com/product/yubihsm-2/) M-of-N backup scheme is implemented in software using an abandoned crate
* yubihsm-setup depends on an unpublished crate (https://github.com/Yubico/yubihsmrs)
* yubihsm-setup creates several objects that we don't want and removing them manually is difficult and error prone
* the human interaction with yubihsm-setup complicates our process unnecessarily

This implementation addresses these concerns by:

* driving interaction with the YubiHSM2 using the [yubihsm](https://github.com/iqlusioninc/yubihsm.rs) crate
* implementing only the wrap key creation and splitting logic
* splitting only the wrap key, we do not prepend various YubiHSM2 specific attributes in the key before it's split
