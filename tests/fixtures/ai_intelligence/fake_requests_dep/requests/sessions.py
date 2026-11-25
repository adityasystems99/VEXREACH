"""Fake requests dependency AST fixture for deterministic validation (never imported)."""


class Session:
    def prepare_request(self, request):
        return request

    def request(self, method, url, **kwargs):
        return (method, url)


def get(url, params=None, **kwargs):
    return Session().request("GET", url, **kwargs)
