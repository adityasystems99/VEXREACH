import yaml
from . import b


def start():
    return b.middle()


def finalize():
    return yaml.load("cyclic: true", Loader=None)
