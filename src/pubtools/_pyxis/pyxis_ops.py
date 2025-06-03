import json
import sys
import tempfile
from argparse import ArgumentParser, Namespace
from typing import Any

from .constants import DEFAULT_REQUEST_THREADS_LIMIT
from .pyxis_authentication import PyxisKrbAuth, PyxisSSLAuth, PyxisAuth
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

UPLOAD_SIGNATURES_ARGS = CMD_ARGS.copy()
UPLOAD_SIGNATURES_ARGS[("--signatures",)] = {
    "help": "Signatures in JSON format (as a string) or an @-prefixed file path"
    " with JSON, e.g. --signatures=@/tmp/filename.json",
    "required": True,
    "type": str,
}
UPLOAD_SIGNATURES_ARGS[("--request-threads",)] = {
    "help": "Maximum number of threads to use for parallel requests",
    "required": False,
    "default": DEFAULT_REQUEST_THREADS_LIMIT,
    "type": int,
}

GET_SIGNATURES_ARGS = CMD_ARGS.copy()
GET_SIGNATURES_ARGS[("--manifest-digest",)] = {
    "help": "comma separated manifest-digests to search or json file when prefixed with @",
    "required": False,
    "type": str,
}
GET_SIGNATURES_ARGS[("--reference",)] = {
    "help": "comma separated container pull reference to search or json file when prefixed with @",
    "required": False,
    "type": str,
}

DELETE_SIGNATURES_ARGS = CMD_ARGS.copy()
DELETE_SIGNATURES_ARGS[("--ids",)] = {
    "help": "comma separated signature IDs to remove or json file when prefixed with @",
    "required": True,
    "type": str,
}
DELETE_SIGNATURES_ARGS[("--request-threads",)] = {
    "help": "Maximum number of threads to use for parallel requests",
    "required": False,
    "default": DEFAULT_REQUEST_THREADS_LIMIT,
    "type": int,
}


def setup_pyxis_client(args: Namespace, ccache_file: str) -> PyxisClient:
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
        auth: PyxisAuth = PyxisKrbAuth(
            args.pyxis_krb_principal,
            args.pyxis_server,
            ccache_file,
            args.pyxis_krb_ktfile,
        )
    elif args.pyxis_ssl_crtfile and args.pyxis_ssl_keyfile:
        auth = PyxisSSLAuth(args.pyxis_ssl_crtfile, args.pyxis_ssl_keyfile)
    else:
        raise ValueError(
            "Either Kerberos principal (and optionally keytab) or .crt and .key "
            "files must be provided for Pyxis authentication."
        )

    if hasattr(args, "request_threads"):
        return PyxisClient(
            args.pyxis_server,
            auth=auth,
            verify=not args.pyxis_insecure,
            threads=args.request_threads,
        )
    else:
        return PyxisClient(args.pyxis_server, auth=auth, verify=not args.pyxis_insecure)


def set_get_operator_indices_args() -> ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(GET_OPERATORS_INDICES_ARGS)


def _get_operator_indices(sysargs: list[str] | None = None) -> list[str] | Any:
    """
    Entrypoint for getting operator indices.

    Returns:
        list: Index images satisfying the specified conditions.
    """
    parser = set_get_operator_indices_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        resp = pyxis_client.get_operator_indices(
            args.ocp_versions_range, args.organization
        )
        return resp


def get_operator_indices_main(sysargs: list[str] | None = None) -> int:
    """
    Entrypoint for getting operator indices.

    Returns:
        int: Exit code (0 for success).
    """
    try:
        resp = _get_operator_indices(sysargs)
        json.dump(resp, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return 0
    except Exception as e:
        print(f"Error getting operator indices: {e}", file=sys.stderr)
        return 1


def get_operator_indices_mod(sysargs: list[str] | None = None) -> list[str] | Any:
    """
    Entrypoint for getting operator indices in module mode.

    This function is used when running the script as a module.
    It does not return an exit code, but rather prints the result directly.
    """
    return _get_operator_indices(sysargs)


def set_get_repo_metadata_args() -> ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(GET_REPO_METADATA_ARGS)


def _get_repo_metadata(sysargs: list[str] | None = None) -> dict[Any, Any] | Any:
    """
    Entrypoint for getting repository metadata.

    Returns:
        dict: Metadata of the repository.
    """
    parser = set_get_repo_metadata_args()

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
        return res


def get_repo_metadata_main(sysargs: list[str] | None = None) -> dict[Any, Any] | Any:
    """
    Entrypoint for getting repository metadata.

    Returns:
        int: Exit code (0 for success).
    """
    try:
        res = _get_repo_metadata(sysargs)
        json.dump(res, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return 0
    except Exception as e:
        print(f"Error getting repository metadata: {e}", file=sys.stderr)
        return 1


def get_repo_metadata_mod(sysargs: list[str] | None = None) -> dict[Any, Any] | Any:
    """
    Entrypoint for getting repository metadata in module mode.

    This function is used when running the script as a module.
    It does not return an exit code, but rather prints the result directly.
    """
    return _get_repo_metadata(sysargs)
    # No return value, output is printed directly


def set_upload_signatures_args() -> ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(UPLOAD_SIGNATURES_ARGS)


def _upload_signatures(sysargs: list[str] | None = None) -> list[Any]:
    """
    Entrypoint for uploading signatures from JSON or a file.

    Returns:
        list: List of uploaded signatures including auto-populated fields.
    """
    parser = set_upload_signatures_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover

    signatures_json = deserialize_list_from_arg(args.signatures)

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        resp = pyxis_client.upload_signatures(signatures_json)
        return resp


def upload_signatures_main(sysargs: list[str] | None = None) -> int:
    """
    Entrypoint for uploading signatures from JSON or a file.

    Returns:
        int: Exit code (0 for success).
    """
    try:
        resp = _upload_signatures(sysargs)
        json.dump(resp, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return 0
    except Exception as e:
        print(f"Error uploading signatures: {e}", file=sys.stderr)
        return 1


def upload_signatures_mod(sysargs: list[str] | None = None) -> list[Any]:
    """
    Entrypoint for uploading signatures from JSON or a file in module mode.

    This function is used when running the script as a module.
    It does not return an exit code, but rather prints the result directly.
    """
    return _upload_signatures(sysargs)
    # No return value, output is printed directly


def deserialize_list_from_arg(value: str, csv_input: bool = False) -> list[Any] | Any:
    """
    Conditionally load contents of a file if specified in argument value.

    Detects whether the value is a reference to a file (@-prefixed like in
    `gcc -o`, `curl -d`, etc.) and returns its contents in list if applicable;
    otherwise returns the value as a list.
    Examples:
        `{"foo"}` -- plain string, returned as a list
        `@items.json` -- file path; its contents are returned in a list
    """
    if not value.startswith("@"):
        if csv_input:
            # convert comma separated string into list
            return value.split(",")
        # convert json string into list
        return json.loads(value)

    filename = value[1:]

    with open(filename, "r") as f:
        # all file content is returned as list
        return json.load(f)


def serialize_to_csv_from_list(list_value: list[Any]) -> str:
    """Convert a list to comma separated string."""
    return ",".join(list_value)


def set_get_signatures_args() -> ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(GET_SIGNATURES_ARGS)


def _get_signatures(sysargs: list[str] | None = None) -> list[str]:
    """
    Entrypoint for getting container signature metadata.

    Returns:
        list: container signature metadata satisfying the specified conditions.
    """
    parser = set_get_signatures_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"

    csv_references = csv_manifest_digests = None
    if not (args.manifest_digest or args.reference):
        parser.error("Give atleast 1 filter, --manifest-digest and/or --reference")
    if args.manifest_digest:
        csv_manifest_digests = serialize_to_csv_from_list(
            deserialize_list_from_arg(args.manifest_digest, csv_input=True)
        )
    if args.reference:
        csv_references = serialize_to_csv_from_list(
            deserialize_list_from_arg(args.reference, csv_input=True)
        )

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        res = pyxis_client.get_container_signatures(
            csv_manifest_digests, csv_references
        )
        return res


def get_signatures_main(sysargs: list[str] | None = None) -> int:
    """
    Entrypoint for getting container signature metadata.

    Returns:
        int: Exit code (0 for success).
    """
    try:
        res = _get_signatures(sysargs)
        json.dump(res, sys.stdout, sort_keys=True, indent=4, separators=(",", ": "))
        return 0
    except Exception as e:
        print(f"Error getting signatures: {e}", file=sys.stderr)
        return 1


def get_signatures_mod(sysargs: list[str] | None = None) -> list[str]:
    """
    Entrypoint for getting container signature metadata in module mode.

    This function is used when running the script as a module.
    It does not return an exit code, but rather prints the result directly.
    """
    return _get_signatures(sysargs)
    # No return value, output is printed directly


def set_delete_signatures_args() -> ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(DELETE_SIGNATURES_ARGS)


def _delete_signatures(sysargs: list[str] | None = None) -> None:
    """
    Entrypoint for removing existing signatures.

    Returns:
        list: Signatures which were deleted.
    """
    parser = set_delete_signatures_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"

    if args.ids:
        signature_ids = deserialize_list_from_arg(args.ids, csv_input=True)

    with tempfile.NamedTemporaryFile() as tmpfile:
        pyxis_client = setup_pyxis_client(args, tmpfile.name)
        pyxis_client.delete_container_signatures(signature_ids)


def delete_signatures_main(sysargs: list[str] | None = None) -> int:
    """
    Entrypoint for removing existing signatures.

    Returns:
        int: Exit code (0 for success).
    """
    try:
        _delete_signatures(sysargs)
        return 0
    except Exception as e:
        print(f"Error deleting signatures: {e}", file=sys.stderr)
        return 1


def delete_signatures_mod(sysargs: list[str] | None = None) -> None:
    """
    Entrypoint for removing existing signatures in module mode.

    This function is used when running the script as a module.
    It does not return an exit code, but rather prints the result directly.
    """
    return _delete_signatures(sysargs)
    # No return value, output is printed directly
