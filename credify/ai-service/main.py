from fastapi import FastAPI

app = FastAPI(title="Credify AI Service API")

@app.get("/")
def read_root():
    return {"message": "Welcome to Credify AI Service"}
