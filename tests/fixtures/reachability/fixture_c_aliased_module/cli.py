import xml.etree.ElementTree as ET
import typer

cli = typer.Typer()


@cli.command()
def parse_cmd(raw: str):
    return ET.fromstring(raw)
