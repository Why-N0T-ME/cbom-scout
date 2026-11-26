import datetime as dt
import json
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "examples", "demo-app")
SCHEMAS = os.path.join(os.path.dirname(__file__), "schemas")


def make_cert(key=None, cn="test.local", days=365, start=None, hash_alg=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    start = start or dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hash_alg or hashes.SHA256()))
    return key, cert


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


@pytest.fixture
def ec_key():
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture(scope="session")
def cdx_validator():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    reg = referencing.Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        with open(os.path.join(SCHEMAS, name), encoding="utf-8") as fh:
            res = referencing.Resource.from_contents(json.load(fh))
        reg = reg.with_resource(f"http://cyclonedx.org/schema/{name}", res).with_resource(name, res)
    with open(os.path.join(SCHEMAS, "bom-1.6.schema.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    return jsonschema.Draft7Validator(schema, registry=reg)
