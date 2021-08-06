try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


def load_data(filename):
    with open("tests/data/{0}.json".format(filename)) as f:
        return f.read()


def load_response(filename):
    with open("tests/data/responses/{0}.json".format(filename)) as f:
        return f.read()
