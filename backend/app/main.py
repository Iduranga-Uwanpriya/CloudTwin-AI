"""
CloudTwin AI - Main Application Entry Point
Ties all components together and starts the FastAPI server
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.models.schemas import HealthCheck
from backend.app.services.digital_twin import test_localstack_connection

# Import API routers
from backend.app.api import deploy, compliance, audit, anomaly

# ==================== CREATE APP ====================
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# ==================== CORS MIDDLEWARE ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== INCLUDE API ROUTERS ====================
app.include_router(deploy.router, prefix="/api/v1")
app.include_router(compliance.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(anomaly.router, prefix="/api/v1")

# ==================== STATIC FILES ====================
try:
    app.mount("/static", StaticFiles(directory="backend/static"), name="static")
except:
    pass  # Static directory might not exist yet

# ==================== ROOT ENDPOINTS ====================

@app.get("/")
def root():
    """
    Root endpoint - Serves web interface
    """
    try:
        return FileResponse("backend/static/index.html")
    except:
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "running",
            "message": "CloudTwin AI Backend is operational",
            "api_docs": "/docs",
            "note": "Web interface not yet configured"
        }

@app.get("/health", response_model=HealthCheck)
def health_check():
    """
    Health check endpoint
    Tests system components
    """
    localstack_connected = test_localstack_connection()
    
    return HealthCheck(
        status="healthy" if localstack_connected else "degraded",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        localstack_connected=localstack_connected,
        blockchain_valid=True  # Will implement blockchain check later
    )

@app.get("/info")
def system_info():
    """
    System information
    """
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": settings.APP_DESCRIPTION,
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "deploy": "/api/v1/deploy",
            "compliance": "/api/v1/compliance",
            "audit": "/api/v1/audit",
            "anomaly": "/api/v1/anomaly"
        },
        "features": {
            "terraform_parsing": "✅ Working",
            "localstack_deployment": "✅ Working",
            "compliance_checking": "✅ Working",
            "blockchain_audit": "🔄 In Progress",
            "ai_anomaly_detection": "⏳ Planned"
        }
    }

# ==================== STARTUP EVENT ====================

@app.on_event("startup")
async def startup_event():
    """
    Run on application startup
    """
    print(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} starting...")
    print(f"📍 LocalStack endpoint: {settings.LOCALSTACK_ENDPOINT}")
    print(f"📚 API Documentation: http://localhost:8000/docs")
    
    # Test LocalStack connection
    if test_localstack_connection():
        print("✅ LocalStack connected")
    else:
        print("⚠️  LocalStack not connected - start LocalStack to enable full functionality")

# ==================== SHUTDOWN EVENT ====================

@app.on_event("shutdown")
async def shutdown_event():
    """
    Run on application shutdown
    """
    print(f"👋 {settings.APP_NAME} shutting down...")
    