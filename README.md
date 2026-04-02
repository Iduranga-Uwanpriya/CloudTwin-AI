# ☁️ CloudTwin AI - Cloud Compliance Digital Twin

**AI-Powered AWS Infrastructure Compliance Automation Platform**

---

##  Overview

CloudTwin AI is an intelligent cloud compliance platform that creates a digital twin of your AWS infrastructure, automatically checks compliance against security standards, and uses AI to detect anomalies.

### Key Features
-  **Digital Twin**: Simulates AWS infrastructure using LocalStack
-  **IaC Parsing**: Analyzes Terraform configurations
-  **Compliance Engine**: Automated security checks
-  **Blockchain Audit**: Tamper-proof compliance logging
-  **AI Anomaly Detection**: ML-powered threat detection (in development)
-  **Auto-Remediation**: Automated security fixes (in development)

---

## Architecture
```
cloudtwin-ai/
│
├── backend/                    # Core FastAPI Application
│   ├── app/
│   │   ├── main.py            # API entry point
│   │   ├── api/               # REST API routes (deploy, compliance, audit, anomaly, reports)
│   │   ├── services/          # Business logic
│   │   ├── models/            # Pydantic schemas
│   │   ├── compliance/        # Policy-as-Code engine (ISO 27001, NIST 800-53)
│   │   └── config.py          # Configuration
│   └── Dockerfile
│
├── ai_engine/                 # Machine Learning Module
│   ├── ml/
│   │   ├── models.py          # Isolation Forest, One-Class SVM, Autoencoder
│   │   ├── inference.py       # Production inference engine (UNSW-NB15)
│   │   ├── preprocessor.py    # Feature engineering
│   │   └── trainer.py         # Training pipeline
│   ├── train.py               # Standalone training script
│   ├── train_anomaly_models.ipynb  # Kaggle training notebook
│   ├── data-sets/             # Synthetic training data
│   └── saved_models/          # Trained model artifacts
│
├── digital-twin/              # Infrastructure Simulation
│   ├── terraform_templates/   # Sample IaC files
│   ├── localstack_config/     # LocalStack init scripts
│   └── scripts/               # Setup scripts
│
├── blockchain_audit/          # Tamper-Proof Audit Logging
│   ├── hash_chain.py          # SHA-256 hash chain + Merkle Tree
│   └── audit_logs.json        # Audit trail storage
│
├── frontend/                  # React 18 Dashboard
│   └── src/
│       ├── pages/             # Dashboard, Compliance, AnomalyDetection, AuditTrail, Deploy
│       ├── components/        # Sidebar, StatsCard, ComplianceGauge
│       └── services/          # API client
│
├── docker-compose.yml         # Full stack orchestration
└── requirements.txt           # Python dependencies
```

---

##  Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop
- Node.js 18+ (for frontend)

### Installation

1. **Clone Repository**
```bash
git clone <your-repo-url>
cd cloudtwin-ai
```

2. **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

3. **Start Infrastructure**
```bash
# Option A: Using Docker Compose (recommended)
docker-compose up -d

# Option B: Manual LocalStack
docker run -d -p 4566:4566 localstack/localstack
```

4. **Run Backend**
```bash
python -m venv venv
cloudtwin-ai> venv\Scripts\activate
pip install fastapi uvicorn pydantic boto3 python-hcl2
pip install python-multipart
To update, run: python.exe -m pip install --upgrade pip
python  uvicorn backend.app.main:app --reload
```

5. **Access Application**
- Web UI: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Blockchain Audit: http://localhost:8000/api/audit/blockchain

---

##  Usage

### Deploy & Check Compliance

1. **Upload Terraform File**
   - Navigate to http://localhost:8000
   - Click "Choose Terraform File"
   - Select a `.tf` file

2. **Deploy to Digital Twin**
   - Click "Deploy & Check Compliance"
   - System deploys infrastructure to LocalStack

3. **View Results**
   - Compliance score
   - Pass/Fail for each check
   - Recommendations

4. **Audit Trail**
   - All checks logged to blockchain
   - View at `/api/audit/blockchain`

---

##  Testing

### Sample Files

Located in `digital-twin/terraform_templates/`:
- `non_compliant.tf` - Basic S3 bucket (0% compliance)
- `compliant.tf` - Secure S3 bucket (100% compliance)
- `mixed.tf` - Partially compliant infrastructure

### Run Tests
```bash
cd backend
pytest tests/
```

---

## 🎓 Project Status

### Completed
- [x] FastAPI backend with REST API
- [x] Terraform parsing and LocalStack deployment
- [x] S3, EC2, IAM compliance checking (ISO 27001 + NIST 800-53)
- [x] Blockchain audit trail (SHA-256 + Merkle Tree)
- [x] AI anomaly detection (Isolation Forest, One-Class SVM, Autoencoder ensemble)
- [x] UNSW-NB15 dataset training with evaluation metrics
- [x] React 18 dashboard with 5 pages
- [x] HTML report generation with SHA-256 signatures
- [x] Digital twin simulation via LocalStack

---



##  Contributing

This is an academic project. For questions or suggestions:
- Open an issue
- Submit a pull request
- Contact: idurangakekulandara78@gmail.com

---

##  License

Academic Project © 2025

---

##  Author

**Iduranga Kekualndara**  
Final Year Dissertation Project  
UOW 
Supervisor: Buddhika remarathne

---

##  Acknowledgments

- AWS for cloud infrastructure concepts
- LocalStack for local AWS emulation
- FastAPI framework
- Terraform by HashiCorp