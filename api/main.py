import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from config.settings import settings
from database.db import init_db
from logmind.monitoring_service import monitoring_service

# Centralized logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("LogMindAI")


# Initialize database schema
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("LogMind AI application starting...")
    yield
    logger.info("Shutting down LogMind AI background services...")
    if monitoring_service.is_active:
        monitoring_service.stop_monitoring()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Python-Powered Real-Time Log Analysis & Root-Cause Assistant API",
    lifespan=lifespan
)

# Configure CORS narrowly for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)
