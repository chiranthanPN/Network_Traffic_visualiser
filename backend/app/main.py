from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(title="Network Traffic Analyser")
app.include_router(router)


@app.get("/")
def read_root():
    return {"message": "Network Traffic Analyser API"}
