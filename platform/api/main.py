from fastapi import FastAPI

app = FastAPI(title="Automata API")

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}

@app.post("/api/v1/scan")
def scan():
    return {"status": "stub"}

@app.get("/api/v1/results/{id}")
def results(id: str):
    return {"status": "stub", "id": id}
