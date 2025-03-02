from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
from sqlalchemy import func, text

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
        # Add debug output
        print(f"Fetching incidents: limit={limit}, offset={offset}, resolved={resolved}")
        
        # Build query
        query = db.query(SecurityIncident)
        
        if resolved is not None:
            resolved_bool = resolved.lower() == 'true'
            query = query.filter(SecurityIncident.is_resolved == resolved_bool)
        
        # Order by most recent first
        query = query.order_by(SecurityIncident.timestamp.desc())
        
        # Debug output
        total = query.count()
        print(f"Total incidents found in database: {total}")
        
        # Paginate
        incidents = query.limit(limit).offset(offset).all()
        print(f"Returning {len(incidents)} incidents after pagination")
        
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
        
        # Print first incident for debugging
        if len(result["incidents"]) > 0:
            print(f"Sample first incident: {json.dumps(result['incidents'][0], indent=2)}")
            
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

@app.get("/api/threat-intelligence")
async def get_threat_intelligence(
    limit: int = 50, 
    offset: int = 0, 
    source: Optional[str] = None,
    min_severity: Optional[float] = None,
    query: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get threat intelligence data with optional filtering"""
    try:
        # Start with base query
        base_query = db.query(ThreatIntelligence)
        
        # Apply filters if provided
        if source:
            base_query = base_query.filter(ThreatIntelligence.source == source)
        
        if min_severity is not None:
            base_query = base_query.filter(ThreatIntelligence.severity >= min_severity)
            
        # Get total count for pagination
        total_count = base_query.count()
        
        # Apply semantic search if query is provided
        if query:
            # Create analyzer for embeddings
            analyzer = ThreatAnalyzer(db_session=db)
            
            # Get embedding for query
            query_embedding = analyzer.embeddings.get_embedding(query)
            
            # Find similar threats using vector search
            # First, order by cosine similarity between query embedding and threat embeddings
            sql = text("""
                SELECT id, 1 - (embedding <=> :query_embedding) as similarity
                FROM threat_intelligence
                ORDER BY similarity DESC
                LIMIT :limit OFFSET :offset
            """)
            
            result = db.execute(sql, {
                "query_embedding": query_embedding,
                "limit": limit,
                "offset": offset
            })
            
            # Get threat IDs and order them by similarity
            threat_ids = [row[0] for row in result]
            
            # Fetch full threat objects
            threats = []
            if threat_ids:
                # Use SQL's ARRAY_POSITION to preserve the order from the vector search
                ordered_threats = db.query(ThreatIntelligence).filter(
                    ThreatIntelligence.id.in_(threat_ids)
                ).all()
                
                # Re-order based on threat_ids
                id_to_threat = {threat.id: threat for threat in ordered_threats}
                threats = [id_to_threat[id] for id in threat_ids if id in id_to_threat]
            
        else:
            # If no query provided, just paginate
            threats = base_query.order_by(ThreatIntelligence.updated_date.desc())\
                .limit(limit).offset(offset).all()
        
        # Format results
        result = {
            "total": total_count,
            "items": [],
            # Group by source for easier frontend display
            "by_source": {}
        }
        
        # Prepare IOCs, campaigns, and threat actors collections
        iocs = []
        campaigns = []
        threat_actors = []
        vulnerabilities = []
        
        # Process each threat
        for threat in threats:
            # Basic threat info dictionary
            threat_info = {
                "id": threat.id,
                "source": threat.source,
                "reference_id": threat.reference_id,
                "title": threat.title,
                "description": threat.description,
                "severity": threat.severity,
                "published_date": threat.published_date.isoformat() if threat.published_date else None,
                "updated_date": threat.updated_date.isoformat() if threat.updated_date else None,
            }
            
            # Add to appropriate collection based on source
            if threat.source == "CVE":
                vulnerabilities.append(threat_info)
            elif threat.source == "MITRE-TECHNIQUE":
                # Add to IOCs with appropriate type
                if "T1566" in threat.reference_id:  # Phishing
                    iocs.append({
                        **threat_info,
                        "type": "Phishing Indicator",
                        "confidence": 90,
                        "first_seen": threat.published_date.isoformat() if threat.published_date else None,
                        "last_seen": threat.updated_date.isoformat() if threat.updated_date else None,
                        "value": threat.title,
                        "tags": ["phishing", "social-engineering"]
                    })
                else:
                    # Add to threat actors for other MITRE techniques
                    threat_actors.append({
                        **threat_info,
                        "type": "APT",
                        "threat_level": "High" if threat.severity > 7 else "Medium" if threat.severity > 4 else "Low",
                        "origin": "Unknown",
                        "active_since": threat.published_date.strftime("%Y-%m") if threat.published_date else "Unknown",
                        "associated_campaigns": [],
                        "ttps": [threat.reference_id]
                    })
            elif threat.source == "MITRE-GROUP":
                # Add to threat actors
                threat_actors.append({
                    **threat_info,
                    "type": "APT",
                    "threat_level": "High" if threat.severity > 7 else "Medium" if threat.severity > 4 else "Low",
                    "origin": "Unknown",
                    "active_since": threat.published_date.strftime("%Y-%m") if threat.published_date else "Unknown",
                    "associated_campaigns": [],
                    "ttps": []
                })
            else:
                # Add to generic list
                result["items"].append(threat_info)
                
            # Add to source grouping
            if threat.source not in result["by_source"]:
                result["by_source"][threat.source] = []
            result["by_source"][threat.source].append(threat_info)
        
        # Create mock campaigns combining multiple threats
        if threat_actors and vulnerabilities:
            campaigns.append({
                "id": 1,
                "name": "Operation Systematic Surge",
                "description": "A sophisticated campaign targeting multiple vulnerabilities in web applications to gain unauthorized access to sensitive information.",
                "threat_level": "High",
                "status": "Active",
                "first_seen": datetime.datetime.now().replace(month=datetime.datetime.now().month-3).isoformat(),
                "last_activity": datetime.datetime.now().isoformat(),
                "target_sectors": ["Finance", "Healthcare", "Government"],
                "associated_actors": [actor["id"] for actor in threat_actors[:2]],
                "related_iocs": [ioc["id"] for ioc in iocs[:5]] if iocs else []
            })
            
            campaigns.append({
                "id": 2,
                "name": "BlueLight Infiltration",
                "description": "A targeted campaign using spear-phishing techniques to deliver malware that exploits known vulnerabilities.",
                "threat_level": "Medium",
                "status": "Monitoring", 
                "first_seen": datetime.datetime.now().replace(month=datetime.datetime.now().month-6).isoformat(),
                "last_activity": datetime.datetime.now().replace(day=datetime.datetime.now().day-14).isoformat(),
                "target_sectors": ["Energy", "Manufacturing"],
                "associated_actors": [actor["id"] for actor in threat_actors[2:4]] if len(threat_actors) > 3 else [],
                "related_iocs": [ioc["id"] for ioc in iocs[5:10]] if len(iocs) > 5 else []
            })
        
        # Add the collections to the result
        result["iocs"] = iocs
        result["campaigns"] = campaigns
        result["threat_actors"] = threat_actors
        result["vulnerabilities"] = vulnerabilities
        
        return result
        
    except Exception as e:
        logger.error(f"Error retrieving threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threat-intelligence/search")
async def search_threat_intelligence(
    query: str,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Search for threat intelligence data"""
    try:
        # Create analyzer for embeddings
        analyzer = ThreatAnalyzer(db_session=db)
        
        # Get embedding for query
        query_embedding = analyzer.embeddings.get_embedding(query)
        
        # Find similar threats using vector search
        # First, order by cosine similarity between query embedding and threat embeddings
        sql = text("""
            SELECT id, 1 - (embedding <=> :query_embedding) as similarity
            FROM threat_intelligence
            ORDER BY similarity DESC
            LIMIT :limit OFFSET :offset
        """)
        
        result = db.execute(sql, {
            "query_embedding": query_embedding,
            "limit": limit,
            "offset": offset
        })
        
        # Get threat IDs and order them by similarity
        threat_ids = [row[0] for row in result]
        
        # Fetch full threat objects
        threats = []
        if threat_ids:
            # Use SQL's ARRAY_POSITION to preserve the order from the vector search
            ordered_threats = db.query(ThreatIntelligence).filter(
                ThreatIntelligence.id.in_(threat_ids)
            ).all()
            
            # Re-order based on threat_ids
            id_to_threat = {threat.id: threat for threat in ordered_threats}
            threats = [id_to_threat[id] for id in threat_ids if id in id_to_threat]
        
        # Format results
        result = {
            "total": len(threats),
            "items": [
                {
                    "id": threat.id,
                    "source": threat.source,
                    "reference_id": threat.reference_id,
                    "title": threat.title,
                    "description": threat.description,
                    "severity": threat.severity,
                    "published_date": threat.published_date.isoformat() if threat.published_date else None,
                    "updated_date": threat.updated_date.isoformat() if threat.updated_date else None,
                } for threat in threats
            ]
        }
        
        return result
    except Exception as e:
        logger.error(f"Error searching threat intelligence: {e}")
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
    """Get system statistics for dashboard"""
    try:
        # Get incident statistics
        incidents_total = db.query(func.count(SecurityIncident.id)).scalar()
        incidents_unresolved = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.is_resolved == False).scalar()
        incidents_resolved = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.is_resolved == True).scalar()
        
        # Get average severity of incidents
        avg_severity = db.query(func.avg(SecurityIncident.severity)).scalar()
        
        # Get count by severity level
        high_severity = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.severity >= 7).scalar()
        medium_severity = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.severity >= 4, SecurityIncident.severity < 7).scalar()
        low_severity = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.severity < 4).scalar()
        
        # Get recent incidents (last 7 days)
        seven_days_ago = datetime.now() - timedelta(days=7)
        recent_incidents = db.query(func.count(SecurityIncident.id))\
            .filter(SecurityIncident.timestamp >= seven_days_ago).scalar()
        
        # Get threat intelligence statistics
        total_threats = db.query(func.count(ThreatIntelligence.id)).scalar()
        
        # Get threat counts by source
        threat_sources = db.query(
            ThreatIntelligence.source, 
            func.count(ThreatIntelligence.id)
        ).group_by(ThreatIntelligence.source).all()
        
        # Get threat counts by severity
        critical_threats = db.query(func.count(ThreatIntelligence.id))\
            .filter(ThreatIntelligence.severity >= 9).scalar()
        high_threats = db.query(func.count(ThreatIntelligence.id))\
            .filter(ThreatIntelligence.severity >= 7, ThreatIntelligence.severity < 9).scalar()
        medium_threats = db.query(func.count(ThreatIntelligence.id))\
            .filter(ThreatIntelligence.severity >= 4, ThreatIntelligence.severity < 7).scalar()
        low_threats = db.query(func.count(ThreatIntelligence.id))\
            .filter(ThreatIntelligence.severity < 4).scalar()
        
        # Get recent threats (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        recent_threats = db.query(func.count(ThreatIntelligence.id))\
            .filter(ThreatIntelligence.updated_date >= thirty_days_ago).scalar()
            
        # Get recommendations statistics
        total_recommendations = db.query(func.count(RecommendedAction.id)).scalar()
        implemented_recommendations = db.query(func.count(RecommendedAction.id))\
            .filter(RecommendedAction.is_implemented == True).scalar()
        
        # Format the result
        return {
            "incidents": {
                "total": incidents_total,
                "unresolved": incidents_unresolved,
                "resolved": incidents_resolved,
                "recent": recent_incidents,
                "avg_severity": float(avg_severity) if avg_severity else 0,
                "by_severity": {
                    "high": high_severity,
                    "medium": medium_severity,
                    "low": low_severity
                }
            },
            "threat_intelligence": {
                "total": total_threats,
                "recent": recent_threats,
                "by_severity": {
                    "critical": critical_threats,
                    "high": high_threats,
                    "medium": medium_threats,
                    "low": low_threats
                },
                "by_source": {
                    source: count for source, count in threat_sources
                },
                "ioc_counts": {
                    "ip": db.query(func.count(ThreatIntelligence.id))
                        .filter(ThreatIntelligence.source == "IOC-IP").scalar() or 0,
                    "domain": db.query(func.count(ThreatIntelligence.id))
                        .filter(ThreatIntelligence.source == "IOC-DOMAIN").scalar() or 0,
                    "hash": db.query(func.count(ThreatIntelligence.id))
                        .filter(ThreatIntelligence.source == "IOC-HASH").scalar() or 0,
                    "url": db.query(func.count(ThreatIntelligence.id))
                        .filter(ThreatIntelligence.source == "IOC-URL").scalar() or 0
                }
            },
            "recommendations": {
                "total": total_recommendations,
                "implemented": implemented_recommendations,
                "pending": total_recommendations - implemented_recommendations,
                "implementation_rate": (
                    float(implemented_recommendations) / total_recommendations
                    if total_recommendations > 0 else 0
                )
            }
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system/status")
async def get_system_status(db: Session = Depends(get_db)):
    """Get system status information"""
    try:
        # Check database connection
        try:
            # Execute a simple query to check DB connection - use text() function
            result = db.execute(text("SELECT 1")).scalar()
            db_status = "connected" if result == 1 else "disconnected"
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
