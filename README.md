# rshijack [![Build Status][travis-img]][travis] [![Crates.io][crates-img]][crates]

[travis-img]:   https://travis-ci.org/kpcyrd/rshijack.svg?branch=master
[travis]:       https://travis-ci.org/kpcyrd/rshijack
[crates-img]:   https://img.shields.io/crates/v/rshijack.svg
[crates]:       https://crates.io/crates/rshijack

tcp connection hijacker, rust rewrite of [shijack] from 2001.

This was written for TAMUctf 2018, brick house 100. The target was a telnet
server that was protected by 2FA. Since the challenge wasn't authenticated,
there have been multiple solutions for this.  Our solution (cyclopropenylidene)
was waiting until the authentication was done, then inject a tcp packet into
the telnet connection:

    echo 'cat ~/.ctf_flag' | sudo rshijack tap0 172.16.13.20:37386 172.16.13.19:23

After some attempts this command was accepted and executed by the telnet
server, resulting in a tcp packet containing the flag.

![screenshot](docs/2018-02-23-brickhouse-tamuctf.png)

The way this works is by sniffing for a packet of a specific connection, then
read the SEQ and ACK fields. Using that information, it's possible to send a
packet on a raw socket that is accepted by the remote server as valid.

The other tools in that screenshot are [sniffglue] and [arpspoof].

[shijack]: https://packetstormsecurity.com/files/24657/shijack.tgz.html
[sniffglue]: https://github.com/kpcyrd/sniffglue
[arpspoof]: https://su2.info/doc/arpspoof.php

## Docker

If needed, rshijack can be pulled as a docker image. The image is currently
about 10.2MB.

    docker run -it --init --rm --net=host kpcyrd/rshijack eth0 172.16.13.20:37386 172.16.13.19:23

## License

GPLv3+
