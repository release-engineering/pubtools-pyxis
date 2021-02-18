import json
import sys
import tempfile

from .pyxis_authentication import PyxisKrbAuth, PyxisSSLAuth
from .pyxis_client import PyxisClient
from .utils import setup_arg_parser


CMD_ARGS = {
    ("--pyxis-server",): {
        "help": "Pyxis service hostname",
        "required": True,
        "type": str,
    },
    ("--pyxis-insecure",): {
        "help": "Allow insecure connection to Pyxis",
        "required": False,
        "type": bool,
    },
    ("--pyxis-krb-principal",): {
        "help": "Pyxis kerberos principal in form: name@REALM",
        "required": False,
        "type": str,
    },
    ("--pyxis-krb-ktfile",): {
        "help": "Pyxis Kerberos client keytab. Optional. Used for login if TGT is not available.",
        "required": False,
        "type": str,
    },
    ("--pyxis-ssl-crtfile",): {
        "help": "Path to .crt file for the SSL authentication",
        "required": False,
        "type": str,
    },
    ("--pyxis-ssl-keyfile",): {
        "help": "Path to .key file for the SSL authentication",
        "required": False,
        "type": str,
    },
}

GET_OPERATORS_INDICES_ARGS = CMD_ARGS.copy()
GET_OPERATORS_INDICES_ARGS[("--ocp-versions-range",)] = {
    "help": "Supported OCP versions range. "
    "See https://docs.engineering.redhat.com/display/CFC/Delivery",
    "required": True,
    "type": str,
}
GET_OPERATORS_INDICES_ARGS[("--organization",)] = {
    "help": "Organization as understood by IIB",
    "required": False,
    "type": str,
}

GET_REPO_METADATA_ARGS = CMD_ARGS.copy()
GET_REPO_METADATA_ARGS[("--repo-name",)] = {
    "help": "Name of the repository",
    "required": True,
    "type": str,
}
GET_REPO_METADATA_ARGS[("--custom-registry",)] = {
    "help": "Custom registry address. Will be used instead of the default addresses.",
    "required": False,
    "type": str,
}
GET_REPO_METADATA_ARGS[("--only-internal-registry",)] = {
    "help": "Check only internal registry",
    "required": False,
    "type": bool,
}
GET_REPO_METADATA_ARGS[("--only-partner-registry",)] = {
    "help": "Check only partner registry",
    "required": False,
    "type": bool,
}


def setup_pyxis_client(args, ccache_file):
    """
    Set up a PyxisClient instance according to specified parameters.

    Args:
        args (argparse.Namespace)
            Arguments of the program.
        cache_dir (str):
            Path to a file used for storing ccache by Kerberos authentication.

    Returns:
        PyxisClient: Configured PyxisClient instance.
    """
    # If both auths are specified, Kerberos is preferred
    if args.pyxis_krb_principal:
        auth = PyxisKrbAuth(
            args.pyxis_krb_principal,
            args.pyxis_server,
            args.pyxis_krb_ktfile,
            ccache_file,
        )
    elif args.pyxis_ssl_crtfile and args.pyxis_ssl_keyfile:
        auth = PyxisSSLAuth(args.pyxis_ssl_crtfile, args.pyxis_ssl_keyfile)
    else:
        raise ValueError(
            "Either Kerberos principal (and optionally keytab) or .crt and .key "
            "files must be provided for Pyxis authentication."
        )

    return PyxisClient(args.pyxis_server, auth=auth, verify=not args.pyxis_insecure)


def get_operator_indices_main(sysargs=None):
    """
    Entrypoint for getting operator indices.

    Returns:
        list: Index images satisfying the specified conditions.
    """
    parser = setup_arg_parser(GET_OPERATORS_INDICES_ARGS)
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        res = pyxis_client.get_operator_indices(
            args.ocp_versions_range, args.organization
        )

        json.dump(res, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return res


def get_repo_metadata_main(sysargs=None):
    """
    Entrypoint for getting repository metadata.

    Returns:
        dict: Metadata of the repository.
    """
    parser = setup_arg_parser(GET_REPO_METADATA_ARGS)
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"

    if args.only_internal_registry and args.only_partner_registry:
        raise ValueError(
            "Can't check only internal registry as well as only partner registry"
        )

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        res = pyxis_client.get_repository_metadata(
            args.repo_name,
            args.custom_registry,
            args.only_internal_registry,
            args.only_partner_registry,
        )

        json.dump(res, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return res
