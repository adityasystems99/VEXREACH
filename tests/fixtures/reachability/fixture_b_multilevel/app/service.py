from app import parser


def handle_payload(data: str):
    return parser.parse_xml(data)
