from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from pgvector.sqlalchemy import Vector
import datetime
from config import DATABASE_URL, VECTOR_DIMENSION

Base = declarative_base()

# Connect to database
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Create and yield a database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class ThreatIntelligence(Base):
    """Model for storing threat intelligence data from CVE, MITRE, etc."""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(50))  # CVE, MITRE, etc.
    reference_id = Column(String(100), index=True)  # CVE-ID or MITRE technique ID
    title = Column(String(200))
    description = Column(Text)
    severity = Column(Float)  # CVSS score or similar
    published_date = Column(DateTime)
    updated_date = Column(DateTime)
    embedding = Column(Vector(VECTOR_DIMENSION))  # Vector embedding for similarity search
    
    # Relationships
    mitigations = relationship("Mitigation", back_populates="threat")

class Mitigation(Base):
    """Model for storing mitigation strategies for threats"""
    __tablename__ = "mitigations"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threat_intelligence.id"))
    description = Column(Text)
    implementation_details = Column(Text)
    
    # Relationships
    threat = relationship("ThreatIntelligence", back_populates="mitigations")

class SecurityIncident(Base):
    """Model for storing security incidents detected by the system"""
    __tablename__ = "security_incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source_ip = Column(String(50))
    destination_ip = Column(String(50))
    log_source = Column(String(100))  # Firewall, IDS, etc.
    severity = Column(Float)
    description = Column(Text)
    raw_log = Column(Text)
    is_resolved = Column(Boolean, default=False)
    resolution_notes = Column(Text, nullable=True)
    resolution_time = Column(DateTime, nullable=True)
    
    # Relationships
    related_threats = relationship("IncidentThreatRelation", back_populates="incident")
    recommended_actions = relationship("RecommendedAction", back_populates="incident")

class IncidentThreatRelation(Base):
    """Model for mapping security incidents to known threats"""
    __tablename__ = "incident_threat_relations"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("security_incidents.id"))
    threat_id = Column(Integer, ForeignKey("threat_intelligence.id"))
    confidence = Column(Float)  # How confident is the AI that this threat is related
    
    # Relationships
    incident = relationship("SecurityIncident", back_populates="related_threats")
    
class RecommendedAction(Base):
    """Model for storing AI-recommended actions for security incidents"""
    __tablename__ = "recommended_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("security_incidents.id"))
    action_type = Column(String(50))  # Firewall rule, system patch, etc.
    description = Column(Text)
    priority = Column(Integer)  # 1-5 with 1 being highest priority
    is_implemented = Column(Boolean, default=False)
    implementation_notes = Column(Text, nullable=True)
    
    # Relationships
    incident = relationship("SecurityIncident", back_populates="recommended_actions")

class LogTemplate(Base):
    """Model for storing log templates for parsing"""
    __tablename__ = "log_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String(50))  # Fortinet, Linux syslog, etc.
    regex_pattern = Column(String(500))
    field_mapping = Column(Text)  # JSON mapping of regex groups to field names
    description = Column(Text)

def create_tables():
    """Create all tables in the database"""
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    create_tables()
