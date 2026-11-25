from flask import Flask

app = Flask(__name__)


def normalize_status(value: str) -> str:
    return value.strip()


@app.route("/health")
def health():
    return normalize_status(" ok ")
