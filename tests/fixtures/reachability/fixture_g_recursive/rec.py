import yaml


def step_a(n: int, raw: str):
    return step_b(n - 1, raw)


def step_b(n: int, raw: str):
    if n > 0:
        return step_a(n, raw)
    return yaml.load(raw, Loader=None)


if __name__ == "__main__":
    step_a(3, "a: 1")
