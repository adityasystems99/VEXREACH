import click
import yaml


@click.command()
def load_cmd(mode: str, raw: str):
    fn = getattr(yaml, mode)
    return {"mode": mode, "raw_len": len(raw)}
