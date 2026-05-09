from fastapi import FastAPI

app = FastAPI(title="Credify Backend API")

@app.get("/")
def read_root():
    return {"message": "Welcome to Credify Backend API"}
