# ☁️ CloudTwin AI - Cloud Compliance Digital Twin

**AI-Powered AWS Infrastructure Compliance Automation Platform**

---

## 🎯 Overview

CloudTwin AI is an intelligent cloud compliance platform that creates a digital twin of your AWS infrastructure, automatically checks compliance against security standards, and uses AI to detect anomalies.

### Key Features
- 🏗️ **Digital Twin**: Simulates AWS infrastructure using LocalStack
- 📝 **IaC Parsing**: Analyzes Terraform configurations
- ✅ **Compliance Engine**: Automated security checks
- 🔐 **Blockchain Audit**: Tamper-proof compliance logging
- 🤖 **AI Anomaly Detection**: ML-powered threat detection (in development)
- 🔧 **Auto-Remediation**: Automated security fixes (in development)

---

## 🏗️ Architecture
```
cloudtwin-ai/
│
├── backend/                    # Core FastAPI Application
│   ├── app/
│   │   ├── main.py            # API entry point
│   │   ├── api/               # REST API routes
│   │   ├── services/          # Business logic
│   │   ├── models/            # Data schemas
│   │   └── config.py          # Configuration
│   ├── static/                # Web dashboard
│   ├── requirements.txt
│   └── Dockerfile
│
├── ai-engine/                 # Machine Learning Module
│   ├── anomaly_detection.py   # ML model implementation
│   ├── model_training.ipynb   # Training notebook
│   ├── dataset/               # Training data
│   └── saved_models/          # Trained models
│
├── digital-twin/              # Infrastructure Simulation
│   ├── terraform_templates/   # Sample IaC files
│   ├── localstack_config/     # LocalStack setup
│   └── scripts/               # Helper scripts
│
├── blockchain-audit/          # Tamper-Proof Logging
│   ├── hash_chain.py          # Blockchain implementation
│   └── audit_logs.json        # Audit trail storage
│
├── frontend/                  # React Dashboard (planned)
│   └── src/
│
└── docs/                      # Documentation
    ├── architecture_diagram.png
    ├── sequence_diagram.png
    └── api_documentation.md
```

---

## 🚀 Quick Start

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

## 📊 Usage

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

## 🧪 Testing

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

### ✅ Prototype (Feb 2025)
- [x] FastAPI backend
- [x] Terraform parsing
- [x] LocalStack integration
- [x] S3 compliance checking
- [x] Blockchain audit trail
- [x] Web interface

### 🔄 In Development (Mar 2025)
- [ ] AI anomaly detection
- [ ] Auto-remediation engine
- [ ] EC2, RDS, IAM support
- [ ] React dashboard

### ⏳ Planned (Apr 2025)
- [ ] Real AWS integration
- [ ] Advanced ML models
- [ ] Production deployment
- [ ] Comprehensive testing

---

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design & components
- **[API Reference](docs/API.md)** - Endpoint documentation
- **[Development Guide](docs/DEVELOPMENT.md)** - Setup & contribution
- **[Demo Guide](docs/DEMO.md)** - Presentation walkthrough

---

## 🤝 Contributing

This is an academic project. For questions or suggestions:
- Open an issue
- Submit a pull request
- Contact: idurangakekulandara78@gmail.com

---

## 📄 License

Academic Project © 2025

---

## 👤 Author

**Iduranga Kekualndara**  
Final Year Dissertation Project  
UOW 
Supervisor: Buddhika remarathne

---

## 🙏 Acknowledgments

- AWS for cloud infrastructure concepts
- LocalStack for local AWS emulation
- FastAPI framework
- Terraform by HashiCorp