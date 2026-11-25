from fastapi import Depends, FastAPI
import yaml

app = FastAPI()


def get_current_user():
    return "admin"


def process_untrusted(raw_body: str):
    cleaned = raw_body.strip()
    return yaml.load(cleaned, Loader=yaml.FullLoader)


def parse_constant():
    static_cfg = "mode: healthcheck"
    return yaml.load(static_cfg, Loader=yaml.FullLoader)


def parse_safe_loader(user_text: str):
    return yaml.load(user_text, Loader=yaml.SafeLoader)


@app.post("/parse-public")
def public_parse(payload: str):
    return process_untrusted(payload)


@app.get("/parse-auth")
def auth_parse(payload: str, user=Depends(get_current_user)):
    return process_untrusted(payload)


@app.get("/health-cfg")
def health_cfg():
    return parse_constant()


@app.post("/parse-safe")
def safe_parse(payload: str):
    return parse_safe_loader(payload)
