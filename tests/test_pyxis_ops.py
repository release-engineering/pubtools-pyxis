import json

import mock
import pytest
import requests_mock

from pubtools._pyxis import pyxis_ops, utils


def test_argument_groups(capsys):
    args = {
        ("--arg1",): {
            "group": "Group 1",
            "help": "Argument 1",
            "required": True,
            "type": str,
        },
        ("--arg2",): {
            "group": "Group 1",
            "help": "Argument 2",
            "required": True,
            "type": str,
        },
        ("--arg3",): {
            "group": "Group 2",
            "help": "Argument 3",
            "required": True,
            "type": str,
        },
        ("--arg4",): {
            "group": "Group 2",
            "help": "Argument 4",
            "required": True,
            "type": str,
        },
    }

    parser = utils.setup_arg_parser(args)
    parser.print_help()
    out, _ = capsys.readouterr()

    assert "Group 1:" in out
    assert "Group 2:" in out


@mock.patch("pubtools._pyxis.pyxis_ops.json.dump")
@mock.patch("pubtools._pyxis.pyxis_ops.setup_pyxis_client")
def test_arg_parser_required(mock_client, mock_json):
    good_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
    ]
    pyxis_ops.get_operator_indices_main(good_args)
    called_args, _ = mock_client.call_args

    assert called_args[0].ocp_versions_range == "4.5"
    assert called_args[0].pyxis_server == "https://pyxis.engineering.redhat.com/"
    assert called_args[0].organization is None
    assert called_args[0].pyxis_insecure is None
    assert called_args[0].pyxis_krb_ktfile is None
    assert called_args[0].pyxis_krb_principal is None
    assert called_args[0].pyxis_ssl_crtfile is None
    assert called_args[0].pyxis_ssl_keyfile is None


@mock.patch("pubtools._pyxis.pyxis_ops.setup_pyxis_client")
def test_arg_parser_required_missing_server(mock_client):
    missing_server = ["dummy", "--ocp-versions-range", "4.5"]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.get_operator_indices_main(missing_server)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2


@mock.patch("pubtools._pyxis.pyxis_ops.setup_pyxis_client")
def test_arg_parser_required_missing_ocp_versions(mock_client):
    missing_ocp_versions = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
    ]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.get_operator_indices_main(missing_ocp_versions)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2


@mock.patch("pubtools._pyxis.pyxis_ops.json.dump")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_krb_verification(mock_kerberos, mock_ssl, mock_client, mock_json):
    good_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
        "--pyxis-krb-principal",
        "name@REDHAT.COM",
    ]
    pyxis_ops.get_operator_indices_main(good_args)

    mock_kerberos.assert_called_once()
    mock_ssl.assert_not_called()


@mock.patch("pubtools._pyxis.pyxis_ops.json.dump")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_ssl_verification(mock_kerberos, mock_ssl, mock_client, mock_json):
    good_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]
    pyxis_ops.get_operator_indices_main(good_args)

    mock_kerberos.assert_not_called()
    mock_ssl.assert_called_once()


@mock.patch("pubtools._pyxis.pyxis_ops.json.dump")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_both_verifications_krb_used(
    mock_kerberos, mock_ssl, mock_client, mock_json
):
    good_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--pyxis-krb-principal",
        "name@REDHAT.COM",
    ]
    pyxis_ops.get_operator_indices_main(good_args)

    mock_kerberos.assert_called_once()
    mock_ssl.assert_not_called()


@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_no_verification(mock_kerberos, mock_ssl, mock_client):
    bad_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_main(bad_args)

    mock_kerberos.assert_not_called()
    mock_ssl.assert_not_called()


@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_missing_ssl_option(mock_kerberos, mock_ssl, mock_client):
    bad_args = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_main(bad_args)

    bad_args2 = [
        "dummy",
        "--pyxis-server",
        "https://pyxis.engineering.redhat.com/",
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_main(bad_args2)

    mock_kerberos.assert_not_called()
    mock_ssl.assert_not_called()


def test_get_operator_indices(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    images = ["registry.io/index-image:4.5", "registry.io/index-image:4.6"]
    data = [{"path": image, "something": "else"} for image in images]
    ver = "4.5-4.6"
    org = "redhat"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ocp-versions-range",
        ver,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--organization",
        org,
    ]

    expected = json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/operators/indices?ocp_versions_range={1}&organization={2}".format(
                hostname, ver, org
            ),
            json={"data": data},
        )
        pyxis_ops.get_operator_indices_main(args)

    out, _ = capsys.readouterr()
    assert out == expected


def test_get_repository_metadata_no_restriction(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.access.redhat.com"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--repo-name",
        repo_name,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    expected = json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )
        pyxis_ops.get_repo_metadata_main(args)

    out, _ = capsys.readouterr()
    assert out == expected


def test_get_repository_metadata_both_restrictions_specified(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    repo_name = "some-repo/name"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--repo-name",
        repo_name,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--only-internal-registry",
        "--only-partner-registry",
    ]

    with pytest.raises(ValueError, match="Can't check only internal registry.*"):
        pyxis_ops.get_repo_metadata_main(args)


def test_get_repository_metadata_no_restriction_partner_registry(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    internal_registry = "registry.access.redhat.com"
    partner_registry = "registry.connect.redhat.com"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--repo-name",
        repo_name,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    expected = json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, internal_registry, repo_name
            ),
            text="no data",
            status_code=404,
        )
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, partner_registry, repo_name
            ),
            json=data,
        )
        pyxis_ops.get_repo_metadata_main(args)

    out, _ = capsys.readouterr()
    assert out == expected


def test_get_repository_metadata_only_internal(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.access.redhat.com"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--repo-name",
        repo_name,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--only-internal-registry",
    ]

    expected = json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )
        pyxis_ops.get_repo_metadata_main(args)

    out, _ = capsys.readouterr()
    assert out == expected


def test_get_repository_metadata_only_partner(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "registry.connect.redhat.com"

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--repo-name",
        repo_name,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--only-partner-registry",
    ]

    expected = json.dumps(data, sort_keys=True, indent=4, separators=(",", ": "))

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            json=data,
        )
        pyxis_ops.get_repo_metadata_main(args)

    out, _ = capsys.readouterr()
    assert out == expected
