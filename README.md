# cryptobin
It's like Uber, but for "secure" paste bins.

A Brno University of Technology, Faculty of Electrical Engineering and Communication, TAKR (Applied Cryptography) class project.

Mostly just an exercise in PKI, Python 3 and `argparse`, TBH.


## License

BSD 2-clause. For the full license text, see the `LICENSE` file.

Not fit for any purpose whatsoever (see Disclaimer below).


## Disclaimer

School project -- abandonware.


## Requirements

* Python 3.5.1 (other 3.x versions untested)
* pyOpenSSL & OpenSSL with TLSv1.2 support
* Linux / OS X (potentially Windows, untested)


## Usage

TL;DR: You're screwed.

First, create a Certificate Authority with `./cryptobin.py ca generate`.
You can do the same for client(s) and server(s): `./cryptobin.py client generate` & `./cryptobin.py server generate`.

The `generate` command accepts options for all the X.509 fields, so feel free to customize (see `./cryptobin.py ca generate --help` for a list). (Come to think of it, I should have made `generate` a first-level subcommand instead of second-level...)

Time to get the CA to sign both client and server certificates! Do that with: `./cryptobin.py ca sign /path/to/cert.pem /path/to/ca-signed-cert.pem`.
Once signed, import the respective certificates with `./cryptobin.py client import --my /path/to/ca-signed-cert.pem` for client(s), analogically for server(s). Make sure you're importing the right certificates. :) Shell pipes work, too: `./cryptobin.py ca sign ~/.cryptobin/client.pem | ./cryptobin.py client import --my -`.

All that's left from the required PKI shenanigans is for client(s) and server(s) to trust the CA... Use `./cryptobin.py client import --ca /path/to/ca.pem` for that, same for server.

Now that we have the PKI sorted out, we may proceed to taking over the wo... -- err, I mean starting the server: `./cryptobin.py server start`. By default it listens on port `1337` (a bit cliché, but oh well) and religiously checks client certificates agains a list of trusted CAs. Once a client passed the certificate check, it gets a shell on the server, sort of (hello there, XML RPC!).

Assuming the client wants to behave, it's allowed to upload and download files via the XML RPC. To upload a file, run `./cryptobin.py client put /path/to/file.txt` (also accepts `-` or no param at all for stdin). On the server, uploads are stored under `~/.cryptobin/server-storage` with the filenames being their SHA1 hashes. By default the client connects to `localhost:1337` -- change that either with `--address` and `--port` options or in the `~/.cryptobinrc` config file (which gets created the first time you run cryptobin, even if it's just to get `--help`).

Downloads work the same way, except in reverse (duh): `./cryptobin.py client get HASH`. This command spits the contents of downloaded file directly to stdout -- can be shell-redirected to a file or you can pass a local file path as an additional argument and it will be saved there.


## Known Issues

Python XMLRPC is insecure, so make sure you trust both client and server -- ie. run them yourself... or just don't use this PoC script at all.
