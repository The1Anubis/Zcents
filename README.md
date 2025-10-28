Zcents 6.10.0
<img align="right" width="120" height="80" src="doc/imgs/logo.png">
=============

What is Zcents?
--------------

[Zcents](https://z.cash/) is a variation of Zcash created for testing
purposes. It builds upon the Zcash codebase and inherits its goals of
providing HTTPS for money while offering an isolated environment for
experimentation. This network is not intended for production use and is
best suited for development, integration testing, and protocol research.

Initially based on Bitcoin's design, Zcents (and Zcash) has been
developed from the Zerocash protocol to offer a far higher standard of
privacy and anonymity. It uses a sophisticated zero-knowledge proving
scheme to preserve confidentiality and hide the connections between
shielded transactions. More technical details are available in the
upstream Zcash [Protocol Specification](https://zips.z.cash/protocol/protocol.pdf).

## The `zcashd` Full Node

This repository hosts the `zcashd` software, adapted as a Zcents
consensus node implementation for testing. It downloads and stores the
entire history of Zcents transactions. Depending on the speed of your
computer and network
connection, the synchronization process could take several days.

<p align="center">
  <img src="doc/imgs/zcashd_screen.gif" height="500">
</p>

The `zcashd` code is derived from a source fork of
[Bitcoin Core](https://github.com/bitcoin/bitcoin). The code was forked
initially from Bitcoin Core v0.11.2, and the two codebases have diverged
substantially.

#### :lock: Security Warnings

See important security warnings on the
[Security Information page](https://z.cash/support/security/).

**Zcents is experimental and a work in progress.** Use it at your own risk.

####  :ledger: Deprecation Policy

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16-week period. The automatic feature is based on block
height.

## Other Zcash Implementations

The [Zebra](https://github.com/ZcashFoundation/zebra) project offers a
different Zcash consensus node implementation, written largely from the
ground up.

## Getting Started

Please see our [user
guide](https://zcash.readthedocs.io/en/latest/rtd_pages/rtd_docs/user_guide.html)
for instructions on joining the main Zcash network.

### Need Help?

* :blue_book: See the documentation at the [ReadTheDocs](https://zcash.readthedocs.io)
  for help and more information.
* :incoming_envelope: Ask for help on the [Zcash forum](https://forum.zcashcommunity.com/).
* :speech_balloon: Join our community on the [Zcash Global Discord](https://discord.com/invite/zcash).
* 🧑‍🎓: Learn at [ZecHub](https://zechub.wiki/)

Participation in the Zcash project is subject to a
[Code of Conduct](code_of_conduct.md).

### Building

Build Zcents along with most dependencies from source by running the following command:

```
./zcutil/build.sh -j$(nproc)
```

Currently, Zcash is only officially supported on Debian and Ubuntu. See the
[Debian / Ubuntu build page](https://zcash.readthedocs.io/en/latest/rtd_pages/Debian-Ubuntu-build.html)
for detailed instructions.

License
-------

For license information see the file [COPYING](COPYING).
