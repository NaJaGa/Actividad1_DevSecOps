from fastapi import FastAPI
import os

app = FastAPI()

aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY", "default_value")

@app.get("/")
def read_root():
    return {"status": "success", "message": "API de E-commerce segura funcionando."}