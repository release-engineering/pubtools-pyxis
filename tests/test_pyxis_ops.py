import json

import mock
import pytest
import requests
import requests_mock

from pubtools._pyxis import pyxis_ops, utils
from tests.utils import load_data, load_response, urljoin


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
def test_arg_parser_required(mock_client, mock_json, hostname):
    good_args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ocp-versions-range",
        "4.5",
    ]
    pyxis_ops.get_operator_indices_main(good_args)
    called_args, _ = mock_client.call_args

    assert called_args[0].ocp_versions_range == "4.5"
    assert called_args[0].pyxis_server == hostname
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
def test_arg_parser_required_missing_ocp_versions(mock_client, hostname):
    missing_ocp_versions = [
        "dummy",
        "--pyxis-server",
        hostname,
    ]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.get_operator_indices_main(missing_ocp_versions)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2


@mock.patch("pubtools._pyxis.pyxis_ops.json.dump")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_krb_verification(
    mock_kerberos, mock_ssl, mock_client, mock_json, hostname
):
    good_args = [
        "dummy",
        "--pyxis-server",
        hostname,
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
def test_arg_parser_ssl_verification(
    mock_kerberos, mock_ssl, mock_client, mock_json, hostname
):
    good_args = [
        "dummy",
        "--pyxis-server",
        hostname,
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
    mock_kerberos, mock_ssl, mock_client, mock_json, hostname
):
    good_args = [
        "dummy",
        "--pyxis-server",
        hostname,
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
def test_arg_parser_no_verification(mock_kerberos, mock_ssl, mock_client, hostname):
    bad_args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ocp-versions-range",
        "4.5",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_mod(bad_args)

    mock_kerberos.assert_not_called()
    mock_ssl.assert_not_called()


@mock.patch("pubtools._pyxis.pyxis_ops.PyxisClient")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisSSLAuth")
@mock.patch("pubtools._pyxis.pyxis_ops.PyxisKrbAuth")
def test_arg_parser_missing_ssl_option(mock_kerberos, mock_ssl, mock_client, hostname):
    bad_args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_mod(bad_args)

    bad_args2 = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ocp-versions-range",
        "4.5",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with pytest.raises(ValueError, match="Either Kerberos principal.*"):
        pyxis_ops.get_operator_indices_mod(bad_args2)

    mock_kerberos.assert_not_called()
    mock_ssl.assert_not_called()


def test_get_operator_indices(capsys, hostname):
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


def test_get_operator_indices_exception(capsys, hostname):
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

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/operators/indices?ocp_versions_range={1}&organization={2}".format(
                hostname, ver, org
            ),
            json={"data": data},
            status_code=500,
        )
        ret = pyxis_ops.get_operator_indices_main(args)

    out, _ = capsys.readouterr()
    assert out == ""
    assert ret == 1


def test_get_repository_metadata_no_restriction(capsys, hostname):
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


def test_get_repository_metadata_main_exception(capsys, hostname):
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

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/repositories/registry/{1}/repository/{2}".format(
                hostname, registry, repo_name
            ),
            status_code=500,
        )
        ret = pyxis_ops.get_repo_metadata_main(args)
        assert ret == 1
    out, _ = capsys.readouterr()
    assert out == ""


def test_get_repository_metadata_both_restrictions_specified(capsys, hostname):
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
        pyxis_ops.get_repo_metadata_mod(args)


def test_get_repository_metadata_no_restriction_partner_registry(capsys, hostname):
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


def test_get_repository_metadata_only_internal(capsys, hostname):
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


def test_get_repository_metadata_only_partner(capsys, hostname):
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


def test_get_repository_metadata_custom_registry(capsys, hostname):
    data = {"metadata": "value", "metadata2": "value2"}
    repo_name = "some-repo/name"
    registry = "some.registry.com"

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
        "--custom-registry",
        registry,
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


def test_upload_signature_json(capsys, hostname):
    items_to_upload = load_data("signatures")
    responses = json.loads(load_response("post_signatures_ok"))

    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
        "--signatures",
        items_to_upload,
    ]

    with requests_mock.Mocker() as m:
        m.post(
            urljoin(hostname, "/v1/signatures"),
            [{"status_code": 200, "json": resp} for resp in responses],
        )

        retval = pyxis_ops.upload_signatures_main(args)
        assert retval == 0

        # assert len(retval) == len(responses)
        # assert all(ret_item in responses for ret_item in retval)

    out, _ = capsys.readouterr()
    print("STDOUT", out)  # For debugging purposes, can be removed later.
    assert all(resp["signature_data"] in out for resp in responses)


def test_upload_signature_file(capsys):
    hostname = "https://pyxis.remote.host/"

    data_file_path = "@tests/data/signatures.json"
    responses = json.loads(load_response("post_signatures_ok"))

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

    with requests_mock.Mocker() as m:
        m.post(
            urljoin(hostname, "/v1/signatures"),
            [{"status_code": 200, "json": resp} for resp in responses],
        )

        retval = pyxis_ops.upload_signatures_main(args)
        assert retval == 0

    out, _ = capsys.readouterr()
    assert all(resp["signature_data"] in out for resp in responses)


def test_upload_signature_error_server(capsys):
    """Test a server-reported error which persists after a few attempts."""
    hostname = "https://pyxis.remote.host/"

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
            pyxis_ops.upload_signatures_mod(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


def test_upload_signature_main_error_server(capsys):
    """Test a server-reported error which persists after a few attempts."""
    hostname = "https://pyxis.remote.host/"

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
        ret = pyxis_ops.upload_signatures_main(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert (
        err == "Error uploading signatures: 402 Client Error: None for "
        "url: https://pyxis.remote.host/v1/signatures\n\n"
    )
    assert ret == 1


def test_upload_signature_error_timeout(capsys):
    """Test a connection error which persists after a few attempts."""
    hostname = "https://pyxis.remote.host/"

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
            pyxis_ops.upload_signatures_mod(args)

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


def test_upload_signatures_server_error_json_detail(capsys):
    """
    Test error response with additional details as JSON.

    Verify that in case of an erroneus response from the server not only the
    status code (e.g. 400) and reason (e.g. "Client Error") are displayed, but
    also the response content, because it may contain crucial information.
    """
    hostname = "https://pyxis.remote.host/"

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
            "{0}v1/signatures".format(hostname),
            status_code=400,
            reason="Crunchy frog",
            text='{"detail": "Extremely nasty"}',
        )

        err_msg = "400 Client Error: Crunchy frog for url: .+\nExtremely nasty"
        with pytest.raises(requests.exceptions.HTTPError, match=err_msg):
            pyxis_ops.upload_signatures_mod(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


def test_upload_signatures_server_error_content(capsys):
    """
    Test error response with additional details as non-JSON content.

    Verify that in case of an error the extra details from the response are
    shown even if we failed to parse the content as JSON.
    """
    hostname = "https://pyxis.remote.host/"

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
            "{0}v1/signatures".format(hostname),
            status_code=400,
            reason="Crunchy frog",
            text="Extra non-JSON info",
        )

        err_msg = "400 Client Error: Crunchy frog for url: .+\nExtra non-JSON info"
        with pytest.raises(requests.exceptions.HTTPError, match=err_msg):
            pyxis_ops.upload_signatures_mod(args)

    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


def test_get_signatures(capsys, hostname):
    all_signatures = signatures_matching = json.loads(load_data("sigs_with_reference"))
    manifest_digest = "sha256:dummy-manifest-digest-1"
    reference = "registry.access.redhat.com/e2e-container/rhel-8-e2e-container-test-product:latest"
    signatures_matching["data"] = all_signatures["data"][0:3]
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--manifest-digest",
        manifest_digest,
        "--reference",
        reference,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    expected = json.dumps(
        signatures_matching["data"], sort_keys=True, indent=4, separators=(",", ": ")
    )

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1}),reference=in=({2})".format(
                hostname, manifest_digest, reference
            ),
            json=signatures_matching,
        )
        pyxis_ops.get_signatures_main(args)
    out, _ = capsys.readouterr()
    assert out == expected


def test_get_signatures_mod(capsys, hostname):
    all_signatures = signatures_matching = json.loads(load_data("sigs_with_reference"))
    manifest_digest = "sha256:dummy-manifest-digest-1"
    reference = "registry.access.redhat.com/e2e-container/rhel-8-e2e-container-test-product:latest"
    signatures_matching["data"] = all_signatures["data"][0:3]
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--manifest-digest",
        manifest_digest,
        "--reference",
        reference,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    expected = signatures_matching["data"]
    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1}),reference=in=({2})".format(
                hostname, manifest_digest, reference
            ),
            json=signatures_matching,
        )
        ret = pyxis_ops.get_signatures_mod(args)
    assert ret == expected


def test_get_signatures_main_error(capsys, hostname):
    all_signatures = signatures_matching = json.loads(load_data("sigs_with_reference"))
    manifest_digest = "sha256:dummy-manifest-digest-1"
    reference = "registry.access.redhat.com/e2e-container/rhel-8-e2e-container-test-product:latest"
    signatures_matching["data"] = all_signatures["data"][0:3]
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--manifest-digest",
        manifest_digest,
        "--reference",
        reference,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1}),reference=in=({2})".format(
                hostname, manifest_digest, reference
            ),
            json=signatures_matching,
            status_code=500,
        )
        pyxis_ops.get_signatures_main(args)
    out, _ = capsys.readouterr()
    assert out == ""


def test_get_signatures_error(capsys, hostname):
    no_filter_args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.get_signatures_main(no_filter_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2


def test_get_signatures_manifests_file(capsys):
    hostname = "https://pyxis.remote.host/"

    data_file_path = "@tests/data/manifest_digests.json"
    signatures_matching = json.loads(load_data("sigs_with_reference"))
    manifest_digest = (
        "sha256:dummy-manifest-digest-1,sha256:sha256:dummy-manifest-digest-2"
    )
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--manifest-digest",
        data_file_path,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    expected = json.dumps(
        signatures_matching["data"], sort_keys=True, indent=4, separators=(",", ": ")
    )

    with requests_mock.Mocker() as m:
        m.get(
            "{0}v1/signatures?filter=manifest_digest=in=({1})".format(
                hostname, manifest_digest
            ),
            json=signatures_matching,
        )
        pyxis_ops.get_signatures_main(args)
    out, _ = capsys.readouterr()
    assert out == expected


def test_delete_signatures_main(hostname):
    ids = "g2g2g2g2,h3h3h3h3"
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ids",
        ids,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with requests_mock.Mocker() as m:
        m.delete("{0}v1/signatures/id/{1}".format(hostname, "g2g2g2g2"))
        m.delete("{0}v1/signatures/id/{1}".format(hostname, "h3h3h3h3"))

        pyxis_ops.delete_signatures_main(args)

        assert len(m.request_history) == 2

        assert set([h.url for h in m.request_history]) == set(
            [
                "{0}v1/signatures/id/{1}".format(hostname, "g2g2g2g2"),
                "{0}v1/signatures/id/{1}".format(hostname, "h3h3h3h3"),
            ]
        )


def test_delete_signatures_mod(hostname):
    ids = "g2g2g2g2,h3h3h3h3"
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ids",
        ids,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with requests_mock.Mocker() as m:
        m.delete("{0}v1/signatures/id/{1}".format(hostname, "g2g2g2g2"))
        m.delete("{0}v1/signatures/id/{1}".format(hostname, "h3h3h3h3"))

        pyxis_ops.delete_signatures_mod(args)

        assert len(m.request_history) == 2

        assert set([h.url for h in m.request_history]) == set(
            [
                "{0}v1/signatures/id/{1}".format(hostname, "g2g2g2g2"),
                "{0}v1/signatures/id/{1}".format(hostname, "h3h3h3h3"),
            ]
        )


def test_delete_signatures_main_error(hostname):
    ids = "g2g2g2g2,h3h3h3h3"
    args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--ids",
        ids,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with requests_mock.Mocker() as m:
        m.delete("{0}v1/signatures/id/{1}".format(hostname, "g2g2g2g2"))
        m.delete(
            "{0}v1/signatures/id/{1}".format(hostname, "h3h3h3h3"), status_code=500
        )

        ret = pyxis_ops.delete_signatures_main(args)
        assert ret == 1


def test_delete_signatures_error(capsys, hostname):
    no_filter_args = [
        "dummy",
        "--pyxis-server",
        hostname,
        "--pyxis-ssl-crtfile",
        "/root/name.crt",
        "--pyxis-ssl-keyfile",
        "/root/name.key",
    ]

    with pytest.raises(SystemExit) as system_error:
        pyxis_ops.delete_signatures_main(no_filter_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
