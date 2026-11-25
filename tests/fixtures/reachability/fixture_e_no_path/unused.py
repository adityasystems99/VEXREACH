import yaml


def dead_legacy_loader(raw: str):
    return yaml.load(raw, Loader=None)
