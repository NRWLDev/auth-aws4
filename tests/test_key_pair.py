import random

from aws4 import key_pair


def test_generate_secret_key():
    secret_access_key = key_pair.generate_secret_access_key()
    assert len(secret_access_key) == 40  # noqa: PLR2004


def test_generate_access_key_id():
    random.seed(0)
    access_key_id = key_pair.generate_access_key_id()
    assert access_key_id == "AKIAY2CQ7ZT6WNISIGQJ"


def test_generate_access_key_id_with_prefix():
    random.seed(0)
    access_key_id = key_pair.generate_access_key_id(prefix="ABCD")
    assert access_key_id == "ABCDY2CQ7ZT6WNISIGQJ"


def test_generate_key_pair():
    random.seed(0)
    kp = key_pair.generate_key_pair()
    assert len(kp.secret_access_key) == 40  # noqa: PLR2004
    assert kp.access_key_id == "AKIAY2CQ7ZT6WNISIGQJ"


def test_generate_key_pair_with_prefix():
    random.seed(0)
    kp = key_pair.generate_key_pair(prefix="ABCD")
    assert len(kp.secret_access_key) == 40  # noqa: PLR2004
    assert kp.access_key_id == "ABCDY2CQ7ZT6WNISIGQJ"
