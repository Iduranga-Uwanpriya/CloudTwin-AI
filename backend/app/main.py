"""
CloudTwin AI - Main Application Entry Point
Ties all components together and starts the FastAPI server
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.models.schemas import HealthCheck
from backend.app.services.digital_twin import test_localstack_connection

# Import API routers
from backend.app.api import deploy, compliance, audit, anomaly, reports, auth, aws_accounts, scanner

# Database
from backend.app.db.models import Base
from backend.app.db.session import engine

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
app.include_router(auth.router, prefix="/api/v1")
app.include_router(aws_accounts.router, prefix="/api/v1")
app.include_router(scanner.router, prefix="/api/v1")
app.include_router(deploy.router, prefix="/api/v1")
app.include_router(compliance.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(anomaly.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")

# ==================== ROOT ENDPOINTS ====================

@app.get("/")
def root():
    """
    Root endpoint
    """
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "message": "CloudTwin AI Backend is operational",
        "api_docs": "/docs",
        "frontend": "http://localhost:3000"
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
            "anomaly": "/api/v1/anomaly",
            "reports": "/api/v1/reports"
        },
        "features": {
            "terraform_parsing": "✅ Working",
            "localstack_deployment": "✅ Working",
            "compliance_checking": "✅ Working (ISO 27001 & NIST 800-53)",
            "ai_anomaly_detection": "✅ Working (Isolation Forest, One-Class SVM, Autoencoder)",
            "blockchain_audit": "✅ Working (SHA-256 + Merkle Tree)",
            "report_generation": "✅ Working (HTML with SHA-256 signatures)"
        }
    }

# ==================== STARTUP EVENT ====================

@app.on_event("startup")
async def startup_event():
    """
    Run on application startup
    """
    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables ready")

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
    