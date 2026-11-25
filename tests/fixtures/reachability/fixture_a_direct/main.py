import yaml


def load_config(raw: str):
    return yaml.load(raw, Loader=yaml.FullLoader)


if __name__ == "__main__":
    yaml.load("a: 1", Loader=yaml.SafeLoader)
