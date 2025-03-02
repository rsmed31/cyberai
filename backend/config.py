import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "cybersecurity_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# Database connection string
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# API keys and external services
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # Comment out or remove
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")  # Add Google API key
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")

# Vector database settings
VECTOR_DIMENSION = 1536  # Default for OpenAI embeddings

# Paths for log files and sample data
LOG_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
SAMPLE_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
MODEL_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")

# Security thresholds and settings
ALERT_THRESHOLD = 0.85  # Confidence threshold for security alerts
MAX_LOG_AGE_DAYS = 30  # Maximum age of logs to keep

# API and server settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"

# Threat intelligence sources
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_ATTACK_URL = "https://attack.mitre.org/versions/v12/techniques/"
