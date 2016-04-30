#!/usr/bin/env python3
''' You know, for security. '''
import io
import os
import abc
import ssl
import sys
import pickle
import getpass
import hashlib
import argparse
import datetime
import configparser
import xmlrpc.client
import xmlrpc.server

import OpenSSL  # pip3 install pyOpenSSL


class Role(abc.ABC):
    ''' abstract class implementing features common to all roles '''
    def __init__(self, args):
        ''' just store the parsed program arguments '''
        self._args = args

    @abc.abstractmethod
    def generate(self):
        '''
        method to generate the required cryptographic material
        for a specific role, must be overriden in all subclasses
        '''
        raise NotImplementedError

    @staticmethod
    def generate_keypair():
        ''' generates a new private/public key pair '''
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
        return key

    def create_csr(self, key):
        ''' creates a certificate signing request '''
        csr = OpenSSL.crypto.X509Req()
        csr.set_pubkey(key)

        subj = csr.get_subject()
        subj.C = self._args.country
        subj.ST = self._args.state
        subj.L = self._args.location
        subj.O = self._args.orgname
        subj.OU = self._args.orgunit
        subj.CN = self._args.cname
        subj.emailAddress = self._args.email

        # prove to CA that we own the corresponding private key
        csr.sign(key, "sha512")

        return csr

    @staticmethod
    def confirm_signing(csr):
        ''' asks for confirmation before signing a CSR '''
        # X.509 extensions not implemented because :effort:,
        # so all certificates can be used for all operations
        # (eg. even a client certificate will be able to act as a CA)

        x509_to_human = {
            "CN": "Common Name",
            "C": "Country",
            "ST": "State",
            "L": "Location",
            "OU": "Organizational Unit",
            "O": "Organization",
            "emailAddress": "e-mail address"
        }

        for key, value in csr.get_subject().get_components():
            print("%s: %s" % (x509_to_human[key.decode("ascii")],
                              value.decode("ascii")),
                  file=sys.stderr)

        # grr, input() can't write the prompt to stderr
        sys.stderr.write("Really sign the above CSR? [yN] ")
        answer = input()
        if answer not in ["y", "Y", "yes", "YES"]:
            print("Not signing...", file=sys.stderr)
            return False

        return True

    def sign_csr(self, csr, cacert, cakey, serial):
        ''' makes CA sign a CSR '''
        cert = OpenSSL.crypto.X509()

        # copy data from CSR
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.set_version(csr.get_version())

        # add CA data
        cert.set_issuer(cacert.get_subject())
        notbefore = datetime.datetime.utcnow()
        cert.set_notBefore(bytes(notbefore.strftime(r"%Y%m%d%H%M%SZ"),
                                 "ascii"))
        notafter = notbefore + datetime.timedelta(
            days=self._args.sign_for_days)
        cert.set_notAfter(bytes(notafter.strftime(r"%Y%m%d%H%M%SZ"),
                                "ascii"))
        cert.set_serial_number(serial)

        cert.sign(cakey, "sha512")

        return cert

    @staticmethod
    def _get_password():
        ''' password prompt for private key encryption '''
        return getpass.getpass().encode("utf_8")

    def write_key(self, key, keyfile):
        ''' dumps private key into a file-like object '''
        dump = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, key,
            cipher="aes-256-cbc", passphrase=self._get_password())
        keyfile.write(dump.decode("ascii"))

    def read_key(self, keyfile):
        ''' loads private key from a file-like object '''
        # the verification done here is enough
        dump = keyfile.read()
        try:
            key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, dump,
                passphrase=self._get_password())
        except OpenSSL.crypto.Error:
            print("Wrong password!", file=sys.stderr)
            sys.exit(1)
        assert key.check(), "Private key corrupt!"
        return key

    @staticmethod
    def write_pub(key, pubfile):
        ''' dumps public key into a file-like object '''
        dump = OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_PEM, key)
        pubfile.write(dump.decode("ascii"))

    @staticmethod
    def read_pub(pubfile):
        ''' loads public key from a file-like object '''
        dump = pubfile.read()
        key = OpenSSL.crypto.load_publickey(
            OpenSSL.crypto.FILETYPE_PEM, dump)
        return key

    @staticmethod
    def write_csr(csr, csrfile):
        ''' dumps CSR into a file-like object '''
        dump = OpenSSL.crypto.dump_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr)
        csrfile.write(dump.decode("ascii"))

    @staticmethod
    def read_csr(csrfile):
        ''' loads CSR from a file-like object '''
        # the verification done here is NOT enough, it only checks that
        # the requester posesses the corresponding private key;
        # you need to do:
        #   * manual subject validation (see `Role.confirm_signing()`)
        dump = csrfile.read()
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, dump)
        assert csr.verify(csr.get_pubkey()), "Invalid requester signature!"
        return csr

    @staticmethod
    def write_crt(crt, crtfile):
        ''' dumps certificate into a file-like object '''
        dump = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, crt)
        crtfile.write(dump.decode("ascii"))

    @staticmethod
    def read_crt(crtfile):
        ''' loads certificate from a file-like object '''
        # no verification done here;
        # you need to check that:
        #   * notBefore and notAfter times are in the past/future
        #   * a trusted CA issued this certificate & the CA signature is valid
        #   * the CA has not revoked this certificate (via CRL or OCSP)
        # The `Role.verify_crt()` function does all except the revoked check
        dump = crtfile.read()
        return OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, dump)

    @staticmethod
    def verify_crt(crt, cacerts):
        ''' verifies a certificate against a list of CA certs '''
        # CA cert must already be verified!
        assert not crt.has_expired(), "Certificate has expired!"

        store = OpenSSL.crypto.X509Store()
        for cacert in cacerts:
            store.add_cert(cacert)
        storectx = OpenSSL.crypto.X509StoreContext(store, crt)
        try:
            storectx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError:
            raise AssertionError("Certificate not signed by the trusted CA!")

    @staticmethod
    def write_serial(ser, serfile):
        ''' dumps most recent CA serial number into a file-like object '''
        serfile.write("%d\n" % ser)

    @staticmethod
    def read_serial(serfile):
        ''' loads most recent CA serial number from a file-like object '''
        return int(serfile.read())

    @staticmethod
    def write_cat(cas, catfile):
        ''' dumps a list of trusted CAs to a file-like object '''
        dump = pickle.dumps(cas)
        catfile.write(dump)

    @staticmethod
    def read_cat(catfile):
        ''' loads a list of trusted CAs from a file-like object '''
        # remeber to check notAfter and CRL/OSCP
        dump = catfile.read()
        return pickle.loads(dump)


class CertificateAuthority(Role):
    ''' the CA role class '''
    def __init__(self, args):
        ''' copy selfsign_for_days arg into sign_for_days '''
        # for easier CA generate() implementation, otherwise sign_csr()
        # would not be able to determine for how long CA cert should be valid
        super().__init__(args)
        if hasattr(self._args, "selfsign_for_days"):
            setattr(self._args, "sign_for_days", self._args.selfsign_for_days)
        self._path = os.path.join(self._args.home, "ca")

    def generate(self):
        ''' generates the whole CA shebang '''
        print("Generating a new keypair...", file=sys.stderr)
        key = self.generate_keypair()
        print("Saving public and encrypted private key...", file=sys.stderr)
        with open("%s.key" % self._path, "w") as keyfile:
            self.write_key(key, keyfile)
        with open("%s.pub" % self._path, "w") as pubfile:
            self.write_pub(key, pubfile)

        print("Creating a Certificate Signing Request.", file=sys.stderr)
        csr = self.create_csr(key)
        with open("%s.csr" % self._path, "w") as csrfile:
            self.write_csr(csr, csrfile)
        print("CSR saved to `%s.csr`, now going to self-sign it."
              % self._path, file=sys.stderr)

        serial = 1
        crt = self.sign_csr(csr, csr, key, serial)
        with open("%s.pem" % self._path, "w") as crtfile:
            self.write_crt(crt, crtfile)

        with open("%s.ser" % self._path, "w") as serfile:
            self.write_serial(serial, serfile)

        print("Successfully self-signed the CA cert."
              " You can give the `%s.pem` file to other people to \"trust\"."
              % self._path, file=sys.stderr)

    def sign(self):
        ''' signs a client, server, or even another CA's CSR '''
        # see the note in confirm_signing()
        for csrfile in self._args.csr:
            csr = self.read_csr(csrfile)
            if self.confirm_signing(csr):
                print("Loading the CA private key to make signature...",
                      file=sys.stderr)
                with open("%s.pem" % self._path) as crtfile:
                    cacert = self.read_crt(crtfile)
                with open("%s.key" % self._path) as keyfile:
                    cakey = self.read_key(keyfile)
                with open("%s.ser" % self._path) as serfile:
                    serial = self.read_serial(serfile) + 1

                cert = self.sign_csr(csr, cacert, cakey, serial)

                with open("%s.ser" % self._path, "w") as serfile:
                    self.write_serial(serial, serfile)
                self.write_crt(cert, self._args.cert)
                print("Certificate successfully signed!", file=sys.stderr)


class Client(Role):
    ''' the client role class '''
    def __init__(self, args):
        super().__init__(args)

        self._path = os.path.join(self._args.home, "client")
        self.trusted_cas = []

        if os.path.isfile("%s.cat" % self._path):
            with open("%s.cat" % self._path, "rb") as catfile:
                self.trusted_cas = self.read_cat(catfile)

    def generate(self):
        '''
        generates a client private key and CSR
        (give CSR to the CA and then import CA-signed cert with "--client")
        '''
        print("Generating a new keypair...", file=sys.stderr)
        key = self.generate_keypair()
        print("Saving public and encrypted private key...", file=sys.stderr)
        with open("%s.key" % self._path, "w") as keyfile:
            self.write_key(key, keyfile)
        with open("%s.pub" % self._path, "w") as pubfile:
            self.write_pub(key, pubfile)

        print("Creating a Certificate Signing Request.", file=sys.stderr)
        csr = self.create_csr(key)
        with open("%s.csr" % self._path, "w") as csrfile:
            self.write_csr(csr, csrfile)
        print("CSR saved to `%s.csr`, give it to your CA to sign"
              " and then import with 'client import --client'."
              " Don't forget to also 'client import --ca' the CA cert!"
              % self._path, file=sys.stderr)

        # create empty CA trust store
        with open("%s.cat" % self._path, "wb") as catfile:
            self.write_cat([], catfile)

    def cert_import(self):
        '''
        imports a certificate;
        either the client's CA-signed cert or a CA cert
        (determined by self._args.cert_type)
        '''
        if self._args.cert_type == "client":
            print("Importing our CA-signed cert...", file=sys.stderr)
            cert = self.read_crt(self._args.cert)
            # make sure it's mine
            with open("%s.pub" % self._path) as pubfile:
                mypub = self.read_pub(pubfile)
            dump1 = OpenSSL.crypto.dump_publickey(
                OpenSSL.crypto.FILETYPE_PEM, mypub)
            dump2 = OpenSSL.crypto.dump_publickey(
                OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
            if dump1 != dump2:
                print("This cert does not have our pubkey on it!",
                      file=sys.stderr)
            # is it signed by a trusted CA? or even signed at all?
            # we shall never know...
            #
            # not really a bug, tho -- I wanna be able to import a signed cert
            # without trusting the issuing CA first (or at all)
            # again, :effort:
            #
            # you could (and should) always manually inspect the stuff CA gives
            # you, anyway as you might even become an intermediary CA
            # by "mistake": https://goo.gl/oEQFMe #topkek
            print("Signed cert is valid, saving.", file=sys.stderr)
            with open("%s.pem" % self._path, "w") as crtfile:
                self.write_crt(cert, crtfile)
        elif self._args.cert_type == "ca":
            print("Importing a new trusted CA cert...", file=sys.stderr)
            cacert = self.read_crt(self._args.cert)
            if cacert.has_expired():
                print("The CA cert has expired!", file=sys.stderr)
                sys.exit(1)
            # not much to verify here, so just save it
            print("Saving CA cert to trusted cacert store.", file=sys.stderr)
            self.trusted_cas.append(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cacert))
            with open("%s.cat" % self._path, "wb") as catfile:
                self.write_cat(self.trusted_cas, catfile)
        else:
            raise NotImplementedError

    def _makectx(self):
        ''' returns a TLS context '''
        # pylint: disable=no-member
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # pylint: enable=no-member

        print("Loading client certificate and private key...", file=sys.stderr)
        ctx.load_cert_chain("%s.pem" % self._path,
                            keyfile="%s.key" % self._path,
                            password=self._get_password)

        for cacert in self.trusted_cas:
            ctx.load_verify_locations(cadata=cacert.decode("utf_8"))

        ctx.set_ciphers("HIGH")
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # not very secure, but oh well
        # at least you don't have to mess with /etc/hosts for a simple PoC

        return ctx

    def put(self):
        ''' uploads a file to a server '''
        ctx = self._makectx()
        uri = "https://%s:%s" % (self._args.address, self._args.port)
        server = xmlrpc.client.ServerProxy(uri, context=ctx)

        for inf in self._args.infile:
            result = server.upload(inf.read())
            print("File uploaded successfully! Hash: %s" % result,
                  file=sys.stderr)

    def get(self):
        ''' downloads a file from a server '''
        ctx = self._makectx()
        uri = "https://%s:%s" % (self._args.address, self._args.port)
        server = xmlrpc.client.ServerProxy(uri, context=ctx)

        result = server.download(self._args.filehash[0])
        self._args.outfile.write(result)
        print("File downloaded successfully!", file=sys.stderr)


class Server(Role):
    ''' the server role class '''
    def __init__(self, args):
        super().__init__(args)
        self._path = os.path.join(self._args.home, "server")

        self.trusted_cas = []

        print("Loading trusted CA certificates...", file=sys.stderr)
        if os.path.isfile("%s.cat" % self._path):
            with open("%s.cat" % self._path, "rb") as catfile:
                self.trusted_cas = self.read_cat(catfile)

    def generate(self):
        '''
        generates a server private key and CSR
        (give CSR to the CA and then import CA-signed cert with "--server")
        '''
        print("Generating a new keypair...", file=sys.stderr)
        key = self.generate_keypair()
        print("Saving public and encrypted private key...", file=sys.stderr)
        with open("%s.key" % self._path, "w") as keyfile:
            self.write_key(key, keyfile)
        with open("%s.pub" % self._path, "w") as pubfile:
            self.write_pub(key, pubfile)

        print("Creating a Certificate Signing Request.", file=sys.stderr)
        csr = self.create_csr(key)
        with open("%s.csr" % self._path, "w") as csrfile:
            self.write_csr(csr, csrfile)
        print("CSR saved to `%s.csr`, give it to your CA to sign"
              " and then import with 'server import --server'."
              " Don't forget to also 'server import --ca' the CA cert!"
              % self._path, file=sys.stderr)

        # create empty CA trust store
        print("Creating an empty CA trust store.", file=sys.stderr)
        with open("%s.cat" % self._path, "wb") as catfile:
            self.write_cat([], catfile)

    def cert_import(self):
        '''
        imports a certificate;
        either a CA cert, client cert or a CA-signed server cert
        (determined by self._args.cert_type)
        '''
        if self._args.cert_type == "server":
            print("Importing our CA-signed cert...", file=sys.stderr)
            cert = self.read_crt(self._args.cert)
            # make sure it's mine
            with open("%s.pub" % self._path) as pubfile:
                mypub = self.read_pub(pubfile)
            dump1 = OpenSSL.crypto.dump_publickey(
                OpenSSL.crypto.FILETYPE_PEM, mypub)
            dump2 = OpenSSL.crypto.dump_publickey(
                OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
            if dump1 != dump2:
                print("This cert does not have our pubkey on it!",
                      file=sys.stderr)
                sys.exit(1)
            print("Signed cert is valid, saving.", file=sys.stderr)
            with open("%s.pem" % self._path, "w") as crtfile:
                self.write_crt(cert, crtfile)
        elif self._args.cert_type == "ca":
            print("Importing a new trusted CA cert...", file=sys.stderr)
            cacert = self.read_crt(self._args.cert)
            if cacert.has_expired():
                print("The CA cert has expired!", file=sys.stderr)
                sys.exit(1)
            # not much to verify here, so just save it
            print("Saving CA cert to trusted cacert store.", file=sys.stderr)
            self.trusted_cas.append(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cacert))
            with open("%s.cat" % self._path, "wb") as catfile:
                self.write_cat(self.trusted_cas, catfile)
        else:
            raise NotImplementedError

    def _makectx(self):
        ''' returns a TLS context '''
        # pylint: disable=no-member
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # pylint: enable=no-member

        print("Loading server certificate and private key...", file=sys.stderr)
        ctx.load_cert_chain("%s.pem" % self._path,
                            keyfile="%s.key" % self._path,
                            password=self._get_password)

        for cacert in self.trusted_cas:
            ctx.load_verify_locations(cadata=cacert.decode("utf_8"))

        ctx.set_ciphers("HIGH")
        ctx.verify_mode = ssl.CERT_REQUIRED

        return ctx

    def start(self):
        ''' starts the network server for secure file up-/downloads '''
        if not (self._args.port > 0 and self._args.port < 65536):
            print("Please choose a valid port number.", file=sys.stderr)
            sys.exit(1)

        # create the storage directory if it does not exist
        if not os.path.isdir("%s-storage" % self._path):
            os.mkdir("%s-storage" % self._path)

        ctx = self._makectx()
        server = xmlrpc.server.SimpleXMLRPCServer(
            (self._args.address, self._args.port), bind_and_activate=False)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.server_bind()
        server.server_activate()

        print("Server listening on %s:%s..."
              % (self._args.address, self._args.port), file=sys.stderr)

        server.register_multicall_functions()
        server.register_function(self.upload, "upload")
        server.register_function(self.download, "download")
        server.serve_forever()

    def upload(self, data):
        ''' handles client uploads -- stores and returns sha1 '''
        data = data.encode("utf_8")
        digest = hashlib.sha1(data).hexdigest()
        with open("%s-storage/%s" % (self._path, digest), "wb") as outf:
            outf.write(data)
        return digest

    def download(self, digest):
        ''' handles client downloads -- sends file by sha1 hash '''
        digest = digest.lower()
        with open("%s-storage/%s" % (self._path, digest)) as inf:
            return inf.read()


class MyConfiguration(object):
    ''' manages the program's configuration file '''
    def __init__(self):
        ''' initializes in-memory config and populates it with defaults '''
        self.cfp = configparser.ConfigParser()

        # set defaults
        self.cfp.add_section("ca")
        self.cfp.set("ca", "selfsign_for_days", "3650")
        self.cfp.set("ca", "sign_for_days", "365")

        self.cfp.add_section("client")
        self.cfp.set("client", "server_address", "localhost")
        self.cfp.set("client", "server_port", "1337")

        self.cfp.add_section("server")
        self.cfp.set("server", "listen_address", "localhost")
        self.cfp.set("server", "listen_port", "1337")

        for role in ["ca", "client", "server"]:
            self.cfp.set(role, "x509_country", "CZ")
            self.cfp.set(role, "x509_state", "Jihomoravsky kraj")
            self.cfp.set(role, "x509_location", "Brno")
            self.cfp.set(role, "x509_orgname", "Brno University of Technology")
            self.cfp.set(role, "x509_orgunit",
                         "Faculty of Electrical Engineering and Communication")
            self.cfp.set(role, "x509_cname", "%s.vutbr.cz" % role)
            self.cfp.set(role, "x509_email", "%s@vutbr.cz" % role)

    def write(self, configfile):
        ''' dumps config into a file-like object '''
        self.cfp.write(configfile)

    def load(self, configfile):
        ''' loads config into a file-like object '''
        self.cfp.read_file(configfile)

    def open(self, path):
        ''' opens & loads config file by path or writes a default one if NX '''
        try:
            cfile = io.open(path)
            self.load(cfile)
            return cfile
        except FileNotFoundError:
            with io.open(path, "w") as cfile:
                self.write(cfile)
            return self.open(path)


def main():
    '''
    pretty much just parses commandline arguments & config file
    and then calls the appropriate class metods
    '''
    parser = argparse.ArgumentParser(
        description="A reasonably secure paste bin.")

    proghome = os.path.join(os.path.expanduser("~"),
                            ".%s" % parser.prog.split(".")[0])
    progrc = "%src" % proghome

    if not os.path.isdir(proghome):
        os.mkdir(proghome)

    config = MyConfiguration()

    # pylint: disable=too-few-public-methods
    class ConfigAction(argparse.Action):
        ''' (re)loads config from file if --config option passed '''
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)
            config.load(values)
    # pylint: enable=too-few-public-methods

    # global options
    parser.add_argument(
        "--home", action="store", default=proghome, metavar="DIRECTORY",
        help="directory for storing certificates; default: %(default)s")
    parser.add_argument(
        "--config", action=ConfigAction, type=argparse.FileType("r"),
        default=config.open(progrc), metavar="FILE",
        help="configuration file; default: %s" % progrc)
    subparsers = parser.add_subparsers(title="Role", dest="role")

    # "ca" subcommand
    parser_ca = subparsers.add_parser("ca", help="certificate authority")
    subparsers_ca = parser_ca.add_subparsers(title="Action", dest="action")

    # "ca generate" subcommand stub, will be filled out later on
    parser_ca_generate = subparsers_ca.add_parser(
        "generate",
        help="generate a new self-signed Certificate Authority certificate")

    # "ca sign" subcommand
    parser_ca_sign = subparsers_ca.add_parser(
        "sign", help="process a CSR (Certificate Signing Request)")
    parser_ca_sign.add_argument(
        "csr", action="store", type=argparse.FileType("r"), nargs=1,
        help="CSR file to process")
    parser_ca_sign.add_argument(
        "cert", action="store", type=argparse.FileType("w"),
        default=sys.stdout, nargs="?",
        help="file to output the signed certificate to; default: -")
    parser_ca_sign.add_argument(
        "--sign-for-days", action="store", type=int, metavar="DAYS",
        default=config.cfp.getint("ca", "sign_for_days"),
        help="how long should the cert be valid; default: %(default)s")

    # "client" subcommand
    parser_client = subparsers.add_parser("client", help="client")
    subparsers_client = parser_client.add_subparsers(
        title="Action", dest="action")

    # "client generate" stub, will be filled out later on
    parser_client_generate = subparsers_client.add_parser(
        "generate", help="generate a new client keypair and CSR")

    # "client import" subcommand
    parser_client_import = subparsers_client.add_parser(
        "import", help="import a certificate")
    parser_client_import.add_argument(
        "cert", action="store", type=argparse.FileType("r"), default=sys.stdin,
        nargs="?", help="certificate file to import; default: -")
    group_certtypes = parser_client_import.add_argument_group(
        "imported certificate type (required)")
    group_certtype = group_certtypes.add_mutually_exclusive_group(
        required=True)
    group_certtype.add_argument(
        "--ca", action="store_const", const="ca", dest="cert_type",
        help="CA certificate")
    group_certtype.add_argument(
        "--my", action="store_const", const="client", dest="cert_type",
        help="CA-signed client certificate")

    # "client put" subcommand
    parser_client_put = subparsers_client.add_parser(
        "put", help="send a file to a server")
    parser_client_put.add_argument(
        "--address", action="store",
        default=config.cfp.get("client", "server_address"),
        help="server to connect to; default: %(default)s")
    parser_client_put.add_argument(
        "--port", action="store", type=int,
        default=config.cfp.getint("client", "server_port"),
        help="server port to connect to; default: %(default)s")
    parser_client_put.add_argument(
        "infile", action="store", type=argparse.FileType("r"),
        default=sys.stdin,
        nargs="*", help="file(s) to upload to the server; default: -")

    # "client get" subcommand
    parser_client_get = subparsers_client.add_parser(
        "get", help="retrieve a file from a server")
    parser_client_get.add_argument(
        "--address", action="store",
        default=config.cfp.get("client", "server_address"),
        help="server to connect to; default: %(default)s")
    parser_client_get.add_argument(
        "--port", action="store", type=int,
        default=config.cfp.getint("client", "server_port"),
        help="server port to connect to; default: %(default)s")
    parser_client_get.add_argument(
        "filehash", action="store", nargs=1,
        help="sha1 hash of the file to download from the server")
    parser_client_get.add_argument(
        "outfile", action="store", type=argparse.FileType("w"),
        default=sys.stdout, nargs="?",
        help="where to save downloaded file; default: -")

    # "server" subcommand
    parser_server = subparsers.add_parser("server", help="server")
    subparsers_server = parser_server.add_subparsers(
        title="Action", dest="action")
    parser_server_generate = subparsers_server.add_parser(
        "generate", help="generate a new server keypair and CSR")
    parser_server_import = subparsers_server.add_parser(
        "import", help="import a certificate")
    parser_server_import.add_argument(
        "cert", action="store", type=argparse.FileType("r"), default=sys.stdin,
        nargs="?", help="certificate file to import; default: -")
    group_certtypes = parser_server_import.add_argument_group(
        "imported certificate type (required)")
    group_certtype = group_certtypes.add_mutually_exclusive_group(
        required=True)
    group_certtype.add_argument(
        "--ca", action="store_const", const="ca", dest="cert_type",
        help="CA certificate")
    group_certtype.add_argument(
        "--my", action="store_const", const="server", dest="cert_type",
        help="CA-signed server certificate")

    parser_server_start = subparsers_server.add_parser(
        "start", help="start accepting client connections")
    parser_server_start.add_argument(
        "--address", action="store",
        default=config.cfp.get("server", "listen_address"),
        help="network address to listen on; default: %(default)s")
    parser_server_start.add_argument(
        "--port", action="store", type=int,
        default=config.cfp.getint("server", "listen_port"),
        help="port to listen on")

    # "generate" subsubcommand options (common to all roles)
    for prsr in [parser_ca_generate, parser_client_generate,
                 parser_server_generate]:
        role = prsr.prog.split()[-2]

        group_x509 = prsr.add_argument_group("X.509 attributes")
        group_x509.add_argument(
            "--country", action="store",
            default=config.cfp.get(role, "x509_country"),
            help="subject country (C); default: %(default)s")
        group_x509.add_argument(
            "--state", action="store",
            default=config.cfp.get(role, "x509_state"),
            help="subject state (S); default: %(default)s")
        group_x509.add_argument(
            "--location", action="store",
            default=config.cfp.get(role, "x509_location"),
            help="subject location (L); default: %(default)s")
        group_x509.add_argument(
            "--orgname", action="store",
            default=config.cfp.get(role, "x509_orgname"),
            help="subject organization name (O); default: %(default)s")
        group_x509.add_argument(
            "--orgunit", action="store",
            default=config.cfp.get(role, "x509_orgunit"),
            help="subject organizational unit name (OU); default: %(default)s")
        group_x509.add_argument(
            "--cname", action="store",
            default=config.cfp.get(role, "x509_cname"),
            help="subject common name (CN); default: %(default)s")
        group_x509.add_argument(
            "--email", action="store",
            default=config.cfp.get(role, "x509_email"),
            help="subject e-mail address (emailAddress); default: %(default)s")

        if role == "ca":
            # other roles generate only a CSR, CA self-signs
            prsr.add_argument(
                "--selfsign-for-days", action="store", metavar="DAYS",
                type=int, default=config.cfp.get(role, "selfsign_for_days"),
                help="how long should the cert be valid; default: %(default)s")

    args = parser.parse_args()

    if args.role is None:
        parser.print_usage()
    elif args.action is None:
        locals()["parser_%s" % args.role].print_usage()
    else:
        # look up class and method by "role" & "action" arguments and execute
        role = {"ca": CertificateAuthority,
                "client": Client,
                "server": Server}[args.role](args)
        # "import" not a valid python method name, gotta rename it
        method_translator = {"import": "cert_import"}
        getattr(role, method_translator.get(args.action, args.action))()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
