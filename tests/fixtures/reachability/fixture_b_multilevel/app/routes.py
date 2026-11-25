from fastapi import FastAPI
from app import service

app = FastAPI()


@app.get("/parse")
def parse_endpoint(data: str):
    return service.handle_payload(data)
