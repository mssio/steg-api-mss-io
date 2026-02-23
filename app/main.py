from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"system": "steg.api.mss.io"}

@app.post("/hide")
def hide():
    return {"foo": "bar"}

@app.post("/show")
def show():
    return {"foo": "bar"}
