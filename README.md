# AI-Powered Cybersecurity Incident Response Assistant

A powerful AI-driven system for automated security log analysis, threat intelligence, and incident response recommendations.

## 🔥 Key Features

### RAG for Real-Time Threat Intelligence
- Pulls information from cybersecurity databases (CVE, MITRE ATT&CK)
- Uses pgvector in PostgreSQL to store, retrieve, and rank threat intelligence
- Semantic similarity search for identifying related threats

### LLM-Powered Incident Analysis
- Uses Google's Generative AI for advanced log analysis and action suggestions
- Identifies attack patterns from logs and suggests firewall rule updates
- Generates detailed incident reports with prioritized recommendations

### Security Log Parsing
- Parses security logs from Fortinet, Linux syslogs, and Azure security logs
- Extracts structured data from raw logs for analysis
- Calculates severity scores based on log content

### Comprehensive API
- Flask/FastAPI-based REST API for all functionality
- Batch log analysis capabilities
- Statistical reporting endpoints for threat intelligence and incidents

### User-Friendly Web Interface
- Dashboard with key security metrics and visualizations
- Interactive log analyzer with threat intelligence integration
- Incident management system with resolution workflows
- Threat intelligence database explorer
- For more details, see the [Web Interface Documentation](web/README.md)

## 🛠️ Tech Stack
- **LLMs & RAG**: Google Generative AI, Hugging Face, TensorFlow
- **Database**: PostgreSQL + pgvector for embeddings
- **Security Tools**: Fortinet, Azure Security Center, Linux logs
- **Backend**: Python (Flask / FastAPI)
- **Frontend**: Bootstrap, JavaScript, Flask templates
- **Retrieval Pipeline**: LangChain
- **Threat Intelligence**: CVE Database, MITRE ATT&CK
- **Vector Search**: pgvector for PostgreSQL

## 📋 Project Structure
```
cyber_ai/
├── backend/                 # Backend code
│   ├── app.py               # Main FastAPI application
│   ├── config.py            # Configuration settings
│   ├── models.py            # Database models
│   ├── threat_analysis.py   # Threat analysis logic
│   └── utils.py             # Utility functions
├── web/                     # Web interface code
│   ├── app.py               # Flask web application
│   ├── templates/           # HTML templates
│   ├── static/              # Static assets (CSS, JS, images)
│   └── README.md            # Web interface documentation
├── embeddings/              # Vector embeddings storage
├── models/                  # ML models storage
├── samples/                 # Sample log files
│   ├── fortinet_logs.txt    # Sample Fortinet logs
│   ├── linux_syslog.txt     # Sample Linux syslog
│   └── azure_waf_logs.txt   # Sample Azure WAF logs
├── venv/                    # Virtual environment
└── requirements.txt         # Python dependencies
```

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- PostgreSQL with pgvector extension
- Google AI Gemini API key (optional, for Google AI Integration)

### Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/cyber_ai.git
cd cyber_ai
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root
```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cybersecurity_db
DB_USER=postgres
DB_PASSWORD=your_password

GOOGLE_AI_API_KEY=your_google_api_key
```

5. Set up PostgreSQL with pgvector
```sql
CREATE DATABASE cybersecurity_db;
\c cybersecurity_db
CREATE EXTENSION vector;
```

6. Initialize the database tables
```bash
cd backend
python models.py
```

### Running the Applications

#### Start the Backend API:
```bash
cd backend
python app.py
```

#### Start the Web Interface:
```bash
cd web
python app.py
```

Access the web interface at http://localhost:5000 (or the configured port)

For more detailed instructions on the web interface, see the [Web Interface Documentation](web/README.md).

## 📊 API Usage Examples

### Analyze a security log
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log": "date=2023-05-15 time=14:32:27 devname=\"FGT60D\" level=\"warning\" srcip=192.168.1.5 dstip=192.168.73.21 action=\"blocked\"", "source_type": "fortinet"}'
```

### Fetch security incidents
```bash
curl -X GET http://localhost:8000/api/incidents?limit=10&offset=0
```

### Update threat intelligence
```bash
curl -X POST http://localhost:8000/api/threat-intelligence/update
```

## 🛡️ Security Considerations

- In a production environment, be sure to:
  - Limit API access with proper authentication
  - Use TLS/SSL for all API endpoints
  - Restrict database access to necessary services only
  - Regularly rotate API keys and credentials
  - Implement IP allowlisting for administrative APIs

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [Google AI](https://ai.google.dev/gemini-api/docs/) for their powerful language models
- [PostgreSQL](https://www.postgresql.org/) and [pgvector](https://github.com/pgvector/pgvector) for vector storage
- [LangChain](https://github.com/hwchase17/langchain) for the retrieval pipelines