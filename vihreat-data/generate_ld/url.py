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
