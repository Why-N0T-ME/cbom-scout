import subprocess


def md5sum(path):
    out = subprocess.run(["md5sum", path], capture_output=True, text=True)
    return out.stdout.split()[0]


def aes(name):
    return {"aes": "에어컨 모드"}.get(name)


sha1_hex = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
rsa_report = {"rsa": "regional sales area"}
