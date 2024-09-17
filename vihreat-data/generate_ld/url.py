import os


_atomic_base_url = "https://atomicdata.dev"
_local_base_url = os.environ["ATOMIC_SERVER_URL"]


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