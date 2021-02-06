import json

import mock
import pytest
import requests
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


def test_upload_signature_json(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"

    data = load_data("signatures")
    response = load_response("post_signatures_ok")

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--signatures",
        data,
    ]
    expected_out = json.dumps(
        json.loads(response), sort_keys=True, indent=4, separators=(",", ": ")
    )

    with requests_mock.Mocker() as m:
        m.post("{0}v1/signatures".format(hostname), text=response)

        pyxis_ops.upload_signatures_main(args)

        assert m.last_request.text == data

    out, _ = capsys.readouterr()
    assert out == expected_out


def test_upload_signature_file(capsys):
    hostname = "https://pyxis.engineering.redhat.com/"

    data_file_path = "@tests/data/signatures.json"
    data = load_data("signatures")
    response = load_response("post_signatures_ok")

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--signatures",
        data_file_path,
    ]
    expected_out = json.dumps(
        json.loads(response), sort_keys=True, indent=4, separators=(",", ": ")
    )

    with requests_mock.Mocker() as m:
        m.post("{0}v1/signatures".format(hostname), text=response)

        pyxis_ops.upload_signatures_main(args)

        assert m.last_request.text.strip() == data.strip()

    out, _ = capsys.readouterr()
    assert out == expected_out


def test_upload_signature_error_server(capsys):
    """Test a server-reported error which persists after a few attempts."""
    hostname = "https://pyxis.engineering.redhat.com/"

    data = load_data("signatures")

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--signatures",
        data,
    ]

    with requests_mock.Mocker() as m:
        m.post("{0}v1/signatures".format(hostname), status_code=402)

        with pytest.raises(requests.exceptions.HTTPError):
            pyxis_ops.upload_signatures_main(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


def test_upload_signature_error_timeout(capsys):
    """Test a connection error which persists after a few attempts."""
    hostname = "https://pyxis.engineering.redhat.com/"

    data = load_data("signatures")

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--signatures",
        data,
    ]

    with requests_mock.Mocker() as m:
        m.post(
            "{0}v1/signatures".format(hostname), exc=requests.exceptions.ConnectTimeout
        )

        with pytest.raises(requests.exceptions.ConnectTimeout):
            pyxis_ops.upload_signatures_main(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


@mock.patch("pubtools._pyxis.pyxis_ops.setup_pyxis_client")
def test_arg_parser_required_missing_arg_signatures(mock_client):
    missing_server = ["dummy"]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.upload_signatures_main(missing_server)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2


def load_data(filename):
    with open("tests/data/{0}.json".format(filename)) as f:
        return f.read()


def load_response(filename):
    with open("tests/data/responses/{0}.json".format(filename)) as f:
        return f.read()
