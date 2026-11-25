from fastapi import FastAPI
import yaml

app = FastAPI()


class Runner:
    def _dispatch(self, raw: str):
        return yaml.load(raw, Loader=None)

    def execute(self, raw: str):
        return self._dispatch(raw)


@app.get("/run")
def outer(payload: str):
    def inner():
        runner = Runner()
        return runner.execute(payload)

    return inner()
