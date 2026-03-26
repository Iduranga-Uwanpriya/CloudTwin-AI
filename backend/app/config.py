"""
Configuration Management
Centralized settings for CloudTwin AI
"""
import os
from pathlib import Path

class Settings:
    """Application configuration settings"""
    
    # ==================== APP INFO ====================
    APP_NAME = "CloudTwin AI"
    APP_VERSION = "1.0.0"
    APP_DESCRIPTION = "Cloud Compliance Digital Twin Platform"
    
    # ==================== AWS/LOCALSTACK ====================
    LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "test")
    AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
    
    # ==================== PATHS ====================
    BASE_DIR = Path(__file__).parent.parent.parent
    BLOCKCHAIN_DIR = BASE_DIR / "blockchain_audit"
    BLOCKCHAIN_LOG_FILE = BLOCKCHAIN_DIR / "audit_logs.json"
    AI_ENGINE_DIR = BASE_DIR / "ai_engine"
    AI_MODELS_DIR = AI_ENGINE_DIR / "saved_models"
    DIGITAL_TWIN_DIR = BASE_DIR / "digital-twin"
    TERRAFORM_TEMPLATES_DIR = DIGITAL_TWIN_DIR / "terraform_templates"
    
    # ==================== COMPLIANCE ====================
    COMPLIANCE_PASS_THRESHOLD = 80.0
    
    # ==================== API ====================
    API_V1_PREFIX = "/api/v1"
    
    def __init__(self):
        """Initialize and create necessary directories"""
        self.BLOCKCHAIN_DIR.mkdir(exist_ok=True, parents=True)
        self.AI_MODELS_DIR.mkdir(exist_ok=True, parents=True)
        self.TERRAFORM_TEMPLATES_DIR.mkdir(exist_ok=True, parents=True)

# Global settings instance
settings = Settings()