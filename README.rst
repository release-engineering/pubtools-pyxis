===============
 pubtools-pyxis
===============

Set of scripts used for operating with Pyxis service.


Requirements
============

* Python 2.7+
* Python 3.7+

Features
========

pubtools-pyxis-get-operator-indices - get a list of index images satisfying the specified conditions
pubtools-pyxis-get-repo-metadata - get metadata of a Comet repo

Setup
=====

::

  $ pip install -r requirements.txt
  $ pip install . 
  or
  $ python setup.py install

Usage
=====

Get operator indices:
::

  pubtools-pyxis-get-operator-indices \
  --pyxis-server https://pyxis.engineering.redhat.com/ \
  --pyxis-krb-principal lgallovi@REDHAT.COM \
  --ocp-versions-range 4.6 \
  --pyxis-insecure

  pubtools-pyxis-get-operator-indices \
  --pyxis-server https://pyxis.engineering.redhat.com/ \
  --pyxis-krb-principal iib-stage@REDHAT.COM \
  --pyxis-krb-ktfile /path/to/file.keytab \
  --ocp-versions-range 4.5-4.7

  pubtools-pyxis-get-operator-indices \
  --pyxis-server https://pyxis.engineering.redhat.com/ \
  --pyxis-ssl-crtfile /path/to/file.crt \
  --pyxis-ssl-keyfile /path/to/file.key \
  --ocp-versions-range 4.6

Get repository metadata:
::

  pubtools-pyxis-get-repo-metadata \
  --pyxis-server https://pyxis.engineering.redhat.com/ \
  --pyxis-ssl-crtfile /path/to/file.crt \
  --pyxis-ssl-keyfile /path/to/file.key \
  --repo-id 123
