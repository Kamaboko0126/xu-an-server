import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# your app code here
@app.get("/")
def home():
    return {"Data":"Test"}

@app.get("/health")
def check_connect_health():
    return {"status":"Success"}

@app.post('/sdada')
def some_function():



    return {"post":"Success"}

if __name__ == "__main__":
    uvicorn.run(app, port=10000)