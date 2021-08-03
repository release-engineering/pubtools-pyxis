import os
import subprocess

from requests_kerberos import HTTPKerberosAuth, OPTIONAL


class PyxisAuth(object):
    """Base Auth class."""

    def __init__(self):
        """Initialize."""
        raise NotImplementedError  # pragma: no cover"

    def apply_to_session(self, pyxis_session):
        """Set up initialization in the Pyxis session."""
        raise NotImplementedError  # pragma: no cover"


class PyxisSSLAuth(PyxisAuth):
    """SSL Auth provider to PyxisClient."""

    # pylint: disable=super-init-not-called
    def __init__(self, crt_path, key_path):
        """
        Initialize.

        Args:
            crt_path (str)
                Path to .crt file (signed certificate).
            key_path (str)
                Path to .key file (private key).
        """
        self.crt_path = crt_path
        self.key_path = key_path

    def apply_to_session(self, pyxis_session):
        """
        Set up PyxisSession with SSL auth.

        Args:
            pyxis_session (PyxisSession)
                PyxisSession instance.
        """
        pyxis_session.session.cert = (self.crt_path, self.key_path)


class PyxisKrbAuth(PyxisAuth):
    """Kerberos authentication support for PyxisClient."""

    def __init__(self, krb_princ, service, ktfile=None, ccache_file=None):
        """
        Initialize.

        Args:
            krb_princ (str)
                Kerberos principal for obtaining ticket.
            service (str)
                URL of the service to apply the authentication to.
            ktfile (str)
                Kerberos client keytab file.
            ccache_file (str)
                Path to a file used for ccache. Only necessary if kinit will be used.
        """
        self.krb_princ = krb_princ
        self.service = service
        self.ktfile = ktfile
        self.ccache_file = ccache_file

    def _krb_auth(self):
        retcode = subprocess.Popen(
            ["klist", "-s"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).wait()

        if retcode or self.ktfile:
            if self.ktfile:
                retcode = subprocess.Popen(
                    [
                        "kinit",
                        self.krb_princ,
                        "-k",
                        "-t",
                        self.ktfile,
                        "-c",
                        self.ccache_file,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).wait()
                os.environ["KRB5CCNAME"] = self.ccache_file
            else:
                # If keytab path wasn't provided, default location will be attempted
                retcode = subprocess.Popen(
                    ["kinit", self.krb_princ, "-k", "-c", self.ccache_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).wait()
                os.environ["KRB5CCNAME"] = self.ccache_file

        # preemptive auth is forced to speed up parallel requests
        return HTTPKerberosAuth(
            mutual_authentication=OPTIONAL,
            force_preemptive=True,
        )

    def apply_to_session(self, pyxis_session):
        """Set up PyxisSession with Kerberos auth.

        Args:
            pyxis_session (PyxisSession)
                PyxisSession instance
        """
        pyxis_session.session.auth = self._krb_auth()
