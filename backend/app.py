from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import sys
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
from sqlalchemy import func  # Add this import at the top

# Fix import path issue
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import API_HOST, API_PORT, DEBUG_MODE

from sqlalchemy.orm import Session
from models import get_db, create_tables, SecurityIncident, ThreatIntelligence, RecommendedAction
from threat_analysis import ThreatAnalyzer
from utils import LogParser

# Initialize logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity Incident Response Assistant API",
    description="AI-Powered API for analyzing security logs and suggesting remediation actions",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables on startup
@app.on_event("startup")
async def initialize_database():
    create_tables()
    logger.info("Database tables created")

# Former Flask routes now as FastAPI endpoints

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/analyze")
async def analyze_log(request: Request, db: Session = Depends(get_db)):
    """Analyze a security log"""
    try:
        data = await request.json()
        if not data or 'log' not in data:
            return JSONResponse({"error": "Log data is required"}, status_code=400)
        
        log_line = data.get('log')
        source_type = data.get('source_type')
        
        # Create analyzer
        analyzer = ThreatAnalyzer(db_session=db)
        
        # Analyze log
        result = analyzer.analyze_log(log_line, source_type)
        
        return result
    except Exception as e:
        logger.error(f"Error analyzing log: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents")
async def get_incidents(limit: int = 10, offset: int = 0, resolved: Optional[str] = None, db: Session = Depends(get_db)):
    """Get list of security incidents"""
    try:
        # Build query
        query = db.query(SecurityIncident)
        
        if resolved is not None:
            resolved_bool = resolved.lower() == 'true'
            query = query.filter(SecurityIncident.is_resolved == resolved_bool)
        
        # Order by most recent first
        query = query.order_by(SecurityIncident.timestamp.desc())
        
        # Paginate
        total = query.count()
        incidents = query.limit(limit).offset(offset).all()
        
        # Format results
        result = {
            "total": total,
            "limit": limit,
            "offset": offset,
            "incidents": []
        }
        
        for incident in incidents:
            # Get recommendations for this incident
            recommendations = db.query(RecommendedAction).filter(
                RecommendedAction.incident_id == incident.id
            ).all()
            
            incident_data = {
                "id": incident.id,
                "timestamp": incident.timestamp.isoformat(),
                "source_ip": incident.source_ip,
                "destination_ip": incident.destination_ip,
                "log_source": incident.log_source,
                "severity": incident.severity,
                "description": incident.description,
                "is_resolved": incident.is_resolved,
                "recommendations": [
                    {
                        "id": rec.id,
                        "action_type": rec.action_type,
                        "description": rec.description,
                        "priority": rec.priority,
                        "is_implemented": rec.is_implemented
                    } for rec in recommendations
                ]
            }
            
            result["incidents"].append(incident_data)
        
        return result
    except Exception as e:
        logger.error(f"Error fetching incidents: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Get a specific security incident with details"""
    try:
        # Get incident
        incident = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get recommendations
        recommendations = db.query(RecommendedAction).filter(
            RecommendedAction.incident_id == incident.id
        ).all()
        
        # Format result
        result = {
            "id": incident.id,
            "timestamp": incident.timestamp.isoformat(),
            "source_ip": incident.source_ip,
            "destination_ip": incident.destination_ip,
            "log_source": incident.log_source,
            "severity": incident.severity,
            "description": incident.description,
            "raw_log": incident.raw_log,
            "is_resolved": incident.is_resolved,
            "resolution_notes": incident.resolution_notes,
            "resolution_time": incident.resolution_time.isoformat() if incident.resolution_time else None,
            "recommendations": [
                {
                    "id": rec.id,
                    "action_type": rec.action_type,
                    "description": rec.description,
                    "priority": rec.priority,
                    "is_implemented": rec.is_implemented,
                    "implementation_notes": rec.implementation_notes
                } for rec in recommendations
            ]
        }
        
        return result
    except Exception as e:
        logger.error(f"Error fetching incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request, db: Session = Depends(get_db)):
    """Mark an incident as resolved"""
    try:
        data = await request.json()
        resolution_notes = data.get('resolution_notes', '')
        
        # Get incident
        incident = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Update incident
        incident.is_resolved = True
        incident.resolution_notes = resolution_notes
        incident.resolution_time = datetime.now()
        
        # Commit changes
        db.commit()
        
        return {"success": True, "message": "Incident marked as resolved"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error resolving incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/recommendations/{recommendation_id}/implement")
async def implement_recommendation(recommendation_id: int, request: Request, db: Session = Depends(get_db)):
    """Mark a recommendation as implemented"""
    try:
        data = await request.json()
        implementation_notes = data.get('implementation_notes', '')
        
        # Get recommendation
        recommendation = db.query(RecommendedAction).filter(
            RecommendedAction.id == recommendation_id
        ).first()
        
        if not recommendation:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        
        # Update recommendation
        recommendation.is_implemented = True
        recommendation.implementation_notes = implementation_notes
        
        # Commit changes
        db.commit()
        
        return {"success": True, "message": "Recommendation marked as implemented"}
    except Exception as e:
        db.rollback()
        logger.error(f"Error implementing recommendation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/threat-intelligence/update")
async def update_threat_intelligence(db: Session = Depends(get_db)):
    """Update threat intelligence database"""
    try:
        # Create analyzer
        analyzer = ThreatAnalyzer(db_session=db)
        
        # Update threat intelligence
        result = analyzer.update_threat_intelligence()
        
        return result
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threat-intelligence/status")
async def get_threat_intelligence_status(db: Session = Depends(get_db)):
    """Get status of threat intelligence database"""
    try:
        # Query the most recent threat intelligence update
        latest = db.query(ThreatIntelligence.updated_date).order_by(
            ThreatIntelligence.updated_date.desc()
        ).first()
        
        return {
            "last_update": latest[0] if latest else None,
            "status": "ok"
        }
    except Exception as e:
        logger.error(f"Error getting threat intelligence status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# FastAPI routes for more complex operations

class LogAnalysisRequest(BaseModel):
    logs: List[str]
    source_type: Optional[str] = None

@app.post("/api/analyze-batch")
async def analyze_logs_batch(
    request: LogAnalysisRequest,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db)
):
    """Analyze multiple logs in batch mode"""
    try:
        # Create analyzer
        analyzer = ThreatAnalyzer(db_session=db)
        
        # Analyze logs
        results = analyzer.analyze_logs(request.logs, request.source_type)
        
        return {"results": results}
    except Exception as e:
        logger.error(f"Error analyzing logs in batch: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get system statistics"""
    try:
        # Get incident counts
        total_incidents = db.query(SecurityIncident).count()
        resolved_incidents = db.query(SecurityIncident).filter(
            SecurityIncident.is_resolved == True
        ).count()
        
        # Get severity distribution
        severity_ranges = [
            (0.0, 0.2, "Low"),
            (0.2, 0.5, "Medium-Low"),
            (0.5, 0.7, "Medium"),
            (0.7, 0.9, "Medium-High"),
            (0.9, 1.0, "High")
        ]
        
        severity_distribution = {}
        for min_val, max_val, label in severity_ranges:
            count = db.query(SecurityIncident).filter(
                SecurityIncident.severity >= min_val,
                SecurityIncident.severity < max_val
            ).count()
            severity_distribution[label] = count
        
        # Get threat intelligence counts
        threat_count = db.query(ThreatIntelligence).count()
        threat_sources = db.query(ThreatIntelligence.source, 
                                  func.count(ThreatIntelligence.id)  # Use imported func here
                                 ).group_by(ThreatIntelligence.source).all()
        
        threat_distribution = {source: count for source, count in threat_sources}
        
        return {
            "incidents": {
                "total": total_incidents,
                "resolved": resolved_incidents,
                "unresolved": total_incidents - resolved_incidents,
                "severity_distribution": severity_distribution
            },
            "threat_intelligence": {
                "total": threat_count,
                "source_distribution": threat_distribution
            }
        }
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system/status")
async def get_system_status(db: Session = Depends(get_db)):
    """Get system status information"""
    try:
        # Check database connection
        try:
            # Execute a simple query to check DB connection
            db.execute(text("SELECT 1")).fetchone()
            db_status = "connected"
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            db_status = "disconnected"
        
        # Check AI model status
        try:
            embeddings_loaded = hasattr(ai_service, 'embedding_model') and ai_service.embedding_model is not None
            llm_loaded = hasattr(ai_service, 'llm') and ai_service.llm is not None
            ai_status = "operational" if embeddings_loaded and llm_loaded else "partial"
            ai_details = {
                "embeddings": "loaded" if embeddings_loaded else "not loaded",
                "language_model": "loaded" if llm_loaded else "not loaded"
            }
        except Exception as e:
            logger.error(f"AI model status error: {e}")
            ai_status = "unknown"
            ai_details = {"error": str(e)}
        
        # Get server information
        server_info = {
            "host": os.getenv("HOST", "0.0.0.0"),
            "port": os.getenv("PORT", 8000),
            "uptime": "N/A"  # You could track this with a start time variable
        }
            
        return {
            "status": "operational" if db_status == "connected" and ai_status == "operational" else "degraded",
            "database": {
                "status": db_status,
                "type": "PostgreSQL"
            },
            "server": {
                "status": "running",
                **server_info
            },
            "ai_models": {
                "status": ai_status,
                **ai_details
            },
            "last_check": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Run the FastAPI app with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=API_HOST, port=API_PORT, reload=True)
