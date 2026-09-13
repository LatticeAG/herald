"""HeraldClient — one-to-one HTTP wrappers (spec §9): submit, query, root,
root_history, status, freshness, events. No additional RPCs.
"""

import json
import urllib.error
import urllib.request

from .strictjson import parse_json_strict, LIMITS_ORDINARY


class HeraldHttpError(Exception):
    def __init__(self, status, code):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class HeraldClient:
    def __init__(self, origin, timeout_ms=2000):
        self.origin = origin.rstrip("/")
        self.timeout = min(max(timeout_ms, 100), 10000) / 1000.0

    def _call(self, method, path, body=None):
        req = urllib.request.Request(self.origin + path, method=method)
        if body is not None:
            req.add_header("content-type", "application/json")
            req.data = bytes(body)
        try:
            res = urllib.request.urlopen(req, timeout=self.timeout)
            status = res.status
            raw = res.read()
        except urllib.error.HTTPError as e:
            status = e.code
            raw = e.read()
        except Exception as e:
            raise HeraldHttpError(0, "UNAVAILABLE") from e
        v, _err = parse_json_strict(raw, _big_limits())
        if status < 200 or status >= 300:
            code = None
            if isinstance(v, dict):
                code = (v.get("error") or {}).get("code")
            raise HeraldHttpError(status, code if isinstance(code, str) else "UNAVAILABLE")
        return v

    def submit(self, command):
        return self._call("POST", f"/v1/roots/{command['body']['root']}/commands",
                          json.dumps(command).encode())

    def query(self, query):
        return self._call("POST", f"/v1/roots/{query['body']['root']}/queries",
                          json.dumps(query).encode())

    def resolve(self, query):
        return self.query(query)

    def export_audit(self, query):
        return self.query(query)

    def receipt(self, query):
        return self.query(query)

    def root(self, root_id):
        return self._call("GET", f"/v1/roots/{root_id}/document")

    def root_history(self, root_id, after="0", limit=64):
        return self._call("GET", f"/v1/roots/{root_id}/documents?after={after}&limit={limit}")

    def status(self, root_id):
        return self._call("GET", f"/v1/roots/{root_id}/status")

    def freshness(self, root_id, challenge):
        body = json.dumps({"v": 1, "challenge": challenge}).encode()
        return self._call("POST", f"/v1/roots/{root_id}/freshness", body)

    def events(self, root_id, after="0", limit=100):
        return self._call("GET", f"/v1/roots/{root_id}/events?after={after}&limit={limit}")


def _big_limits():
    from .strictjson import Limits
    return Limits(1 << 22, 16, 128, 256)
