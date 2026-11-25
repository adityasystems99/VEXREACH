import yaml


def f6(raw: str):
    return yaml.load(raw, Loader=None)


def f5(raw: str):
    return f6(raw)


def f4(raw: str):
    return f5(raw)


def f3(raw: str):
    return f4(raw)


def f2(raw: str):
    return f3(raw)


def f1(raw: str):
    return f2(raw)


if __name__ == "__main__":
    f1("x: 1")
