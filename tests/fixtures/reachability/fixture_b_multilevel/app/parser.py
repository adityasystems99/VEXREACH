from xml.etree import ElementTree


def parse_xml(raw: str):
    return ElementTree.fromstring(raw)
