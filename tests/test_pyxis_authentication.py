import os
import tempfile

import mock

from pubtools._pyxis import pyxis_authentication, pyxis_session


def test_ssl_authentication(hostname):
    crt_path = "/root/name.crt"
    key_path = "/root/name.key"

    ssl_auth = pyxis_authentication.PyxisSSLAuth(crt_path, key_path)
    assert ssl_auth.crt_path == crt_path
    assert ssl_auth.key_path == key_path

    my_pyxis_session = pyxis_session.PyxisSession(hostname)
    ssl_auth.apply_to_session(my_pyxis_session)
    assert my_pyxis_session.session.cert == (crt_path, key_path)


def test_krb_auth_init(hostname):
    krb_princ = "name@REDHAT.COM"
    service = hostname
    ktfile = "/root/file.keytab"

    krb_auth = pyxis_authentication.PyxisKrbAuth(krb_princ, service, "/path", ktfile)
    assert krb_auth.krb_princ == krb_princ
    assert krb_auth.service == service
    assert krb_auth.ktfile == ktfile


@mock.patch.dict("os.environ", {"something": "here"})
@mock.patch("pubtools._pyxis.pyxis_authentication.subprocess.Popen")
def test_krb_auth_use_keytab(mock_popen, hostname):
    krb_princ = "name@REDHAT.COM"
    service = hostname
    ktfile = "/root/file.keytab"

    with tempfile.NamedTemporaryFile() as tmpfile:
        krb_auth = pyxis_authentication.PyxisKrbAuth(
            krb_princ, service, tmpfile.name, ktfile
        )
        mock_wait = mock.MagicMock()
        mock_wait.side_effect = [0, 0, 0]
        mock_popen.return_value.wait = mock_wait

        krb_auth._krb_auth()
        assert mock_popen.call_count == 2
        assert mock_popen.call_args_list == [
            mock.call(["klist", "-s"], stdout=-1, stderr=-1),
            mock.call(
                [
                    "kinit",
                    "name@REDHAT.COM",
                    "-k",
                    "-t",
                    "/root/file.keytab",
                    "-c",
                    tmpfile.name,
                ],
                stdout=-1,
                stderr=-1,
            ),
        ]
        assert os.environ["KRB5CCNAME"] == tmpfile.name


@mock.patch.dict("os.environ", {"something": "here"})
@mock.patch("pubtools._pyxis.pyxis_authentication.subprocess.Popen")
def test_krb_auth_use_default_keytab(mock_popen, hostname):
    krb_princ = "name@REDHAT.COM"
    service = hostname

    with tempfile.NamedTemporaryFile() as tmpfile:
        krb_auth = pyxis_authentication.PyxisKrbAuth(
            krb_princ, service, ccache_file=tmpfile.name
        )
        mock_wait = mock.MagicMock()
        mock_wait.side_effect = [1, 0, 0]
        mock_popen.return_value.wait = mock_wait

        krb_auth._krb_auth()
        assert mock_popen.call_count == 2
        assert mock_popen.call_args_list == [
            mock.call(["klist", "-s"], stdout=-1, stderr=-1),
            mock.call(
                ["kinit", "name@REDHAT.COM", "-k", "-c", tmpfile.name],
                stdout=-1,
                stderr=-1,
            ),
        ]
        assert os.environ["KRB5CCNAME"] == tmpfile.name


@mock.patch.dict("os.environ", {"something": "here"})
@mock.patch("pubtools._pyxis.pyxis_authentication.subprocess.Popen")
def test_krb_auth_skip_init(mock_popen, hostname):
    krb_princ = "name@REDHAT.COM"
    service = hostname

    krb_auth = pyxis_authentication.PyxisKrbAuth(krb_princ, service, "/path")
    mock_wait = mock.MagicMock()
    mock_wait.return_value = 0
    mock_popen.return_value.wait = mock_wait

    krb_auth._krb_auth()
    assert mock_popen.call_count == 1
    assert mock_popen.call_args_list == [
        mock.call(["klist", "-s"], stdout=-1, stderr=-1)
    ]
    assert "KRB5CCNAME" not in os.environ


@mock.patch("pubtools._pyxis.pyxis_authentication.PyxisKrbAuth._krb_auth")
def test_krb_apply_to_session(mock_krb_auth, hostname):
    krb_princ = "name@REDHAT.COM"
    service = hostname
    ktfile = "/root/file.keytab"

    krb_auth = pyxis_authentication.PyxisKrbAuth(krb_princ, service, ktfile, "/path")
    my_pyxis_session = pyxis_session.PyxisSession(hostname)
    krb_auth.apply_to_session(my_pyxis_session)
    assert isinstance(my_pyxis_session.session.auth, mock.MagicMock)
