_atomic_base_url = "https://atomicdata.dev"
_local_base_url = "http://localhost:9883"

class UrlException(Exception):
    pass

def set_local_base_url(url: str):
    global _local_base_url
    _local_base_url = url


def atomic(tail: str = "") -> str:
    if tail:
        return f"{_atomic_base_url}/{tail}"
    else:
        return _atomic_base_url


def local(tail: str = "") -> str:
    if tail:
        return f"{_local_base_url}/{tail}"
    else:
        return _local_base_url

def decode(s: str) -> str:
    if _atomic_base_url in s:
        return s.replace(f"{_atomic_base_url}/", "")
    elif _local_base_url in s:
        return s.replace(f"{_local_base_url}/", "")
    else:
        raise UrlException(f"No base URL found in {s}")