"""
FastAPI Backend for Cybersecurity Anomaly Detection System
Modern REST API with WebSocket support for real-time updates
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import json
import os
import asyncio
import glob
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import uvicorn
from pydantic import BaseModel
import logging
import sys
sys.path.append('..')
from mongodb_utils import get_mongodb_manager, get_anomalies, get_anomaly_stats

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define lifespan handler first
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    # Startup
    logger.info("Initializing MongoDB connection...")
    mongodb_manager = get_mongodb_manager()
    if not mongodb_manager.connect():
        logger.warning("Failed to connect to MongoDB - some features may not work")
    else:
        logger.info("✅ MongoDB connected successfully")
    
    asyncio.create_task(monitor_anomalies())
    logger.info("Anomaly monitoring started")
    yield
    # Shutdown
    logger.info("Disconnecting from MongoDB...")
    mongodb_manager.disconnect()
    logger.info("Application shutting down")

app = FastAPI(
    title="Cybersecurity Anomaly Detection API",
    description="Real-time threat detection and monitoring system",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except:
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.disconnect(conn)

manager = ConnectionManager()

# Pydantic models
class AnomalyResponse(BaseModel):
    timestamp: str
    type: str
    severity: str
    risk_score: float
    details: Dict
    explanation: str

class SystemStats(BaseModel):
    total_anomalies: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    last_updated: str
    system_uptime: str

class AlertAction(BaseModel):
    anomaly_id: str
    action: str  # "acknowledge", "investigate", "resolve", "false_positive"
    notes: Optional[str] = None

# Utility functions - MongoDB implementation
def get_all_anomalies() -> List[Dict]:
    """Get all anomalies from MongoDB with enhanced type detection"""
    try:
        # Get anomalies from MongoDB
        anomalies = get_anomalies(limit=1000)  # Get more than default for complete view
        
        for anomaly in anomalies:
            # Enhanced type detection
            if not anomaly.get('type'):
                if 'username' in anomaly and 'location' in anomaly:
                    anomaly['type'] = 'login'
                elif 'requests_per_minute' in anomaly:
                    anomaly['type'] = 'network'
                elif 'file_size_mb' in anomaly or 'filename' in anomaly:
                    anomaly['type'] = 'file_transfer'
                elif 'anomaly_data' in anomaly:
                    anomaly['type'] = 'unknown_pathway'
                else:
                    anomaly['type'] = 'unknown'
            
            # Ensure required fields exist
            if not anomaly.get('timestamp'):
                anomaly['timestamp'] = datetime.now().isoformat()
            if not anomaly.get('severity'):
                anomaly['severity'] = 'UNKNOWN'
            if not anomaly.get('risk_score'):
                anomaly['risk_score'] = 0
        
        logger.info(f"Total anomalies loaded from MongoDB: {len(anomalies)}")
        return anomalies
        
    except Exception as e:
        logger.error(f"Error retrieving anomalies from MongoDB: {e}")
        return []


def calculate_system_stats() -> SystemStats:
    """Calculate system statistics using MongoDB aggregation"""
    try:
        # Use MongoDB aggregation for efficient stats calculation
        stats = get_anomaly_stats()
        
        return SystemStats(
            total_anomalies=stats.get('total_anomalies', 0),
            critical_count=stats.get('critical_count', 0),
            high_count=stats.get('high_count', 0),
            medium_count=stats.get('medium_count', 0),
            low_count=stats.get('low_count', 0),
            last_updated=datetime.now().isoformat(),
            system_uptime="2h 34m"  # This would be calculated from actual uptime
        )
        
    except Exception as e:
        logger.error(f"Error calculating system stats: {e}")
        # Fallback to counting anomalies
        anomalies = get_all_anomalies()
        
        critical_count = sum(1 for a in anomalies if a.get('severity') == 'CRITICAL')
        high_count = sum(1 for a in anomalies if a.get('severity') == 'HIGH')
        medium_count = sum(1 for a in anomalies if a.get('severity') == 'MEDIUM')
        low_count = sum(1 for a in anomalies if a.get('severity') == 'LOW')
        
        return SystemStats(
            total_anomalies=len(anomalies),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            last_updated=datetime.now().isoformat(),
            system_uptime="2h 34m"
        )

# API Routes
@app.get("/")
async def root():
    return {"message": "Cybersecurity Anomaly Detection API", "status": "running"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies_endpoint(limit: int = 50, severity: Optional[str] = None, 
                                anomaly_type: Optional[str] = None):
    """Get recent anomalies with optional filtering"""
    try:
        # Use MongoDB filtering for better performance
        anomalies = get_anomalies(limit=limit, severity=severity, anomaly_type=anomaly_type)
        
        # Convert to response model
        response = []
        for anomaly in anomalies:
            response.append(AnomalyResponse(
                timestamp=anomaly.get('timestamp', ''),
                type=anomaly.get('type', 'unknown'),
                severity=anomaly.get('severity', 'UNKNOWN'),
                risk_score=anomaly.get('risk_score', 0.0),
                details=anomaly,
                explanation=anomaly.get('explanation', 'No explanation available')
            ))
        
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving anomalies: {e}")
        return []

@app.get("/api/stats", response_model=SystemStats)
async def get_system_stats():
    """Get system statistics"""
    return calculate_system_stats()

@app.get("/api/anomalies/recent")
async def get_recent_anomalies(hours: int = 1):
    """Get anomalies from the last N hours"""
    try:
        # Use MongoDB time-based filtering for better performance
        anomalies = get_anomalies(limit=100, hours=hours)
        return anomalies
        
    except Exception as e:
        logger.error(f"Error retrieving recent anomalies: {e}")
        return []

@app.post("/api/alerts/{anomaly_id}/action")
async def handle_alert_action(anomaly_id: str, action: AlertAction):
    """Handle alert actions (acknowledge, investigate, etc.)"""
    # In a real system, this would update a database
    logger.info(f"Alert action: {action.action} for anomaly {anomaly_id}")
    
    # Broadcast the action to all connected clients
    await manager.broadcast({
        "type": "alert_action",
        "anomaly_id": anomaly_id,
        "action": action.action,
        "notes": action.notes,
        "timestamp": datetime.now().isoformat()
    })
    
    return {"status": "success", "message": f"Action {action.action} applied to alert {anomaly_id}"}

@app.get("/api/anomalies/types")
async def get_anomaly_types():
    """Get breakdown of anomaly types using MongoDB aggregation"""
    try:
        mongodb_manager = get_mongodb_manager()
        if not mongodb_manager.is_connected():
            mongodb_manager.connect()
        
        pipeline = [
            {
                "$group": {
                    "_id": "$type",
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"count": -1}
            }
        ]
        
        results = list(mongodb_manager.anomalies_collection.aggregate(pipeline))
        type_counts = {result["_id"] or "unknown": result["count"] for result in results}
        
        return type_counts
        
    except Exception as e:
        logger.error(f"Error getting anomaly types: {e}")
        return {}

@app.get("/api/anomalies/severity")
async def get_severity_breakdown():
    """Get severity level breakdown using MongoDB aggregation"""
    try:
        mongodb_manager = get_mongodb_manager()
        if not mongodb_manager.is_connected():
            mongodb_manager.connect()
        
        pipeline = [
            {
                "$group": {
                    "_id": "$severity",
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"count": -1}
            }
        ]
        
        results = list(mongodb_manager.anomalies_collection.aggregate(pipeline))
        severity_counts = {result["_id"] or "UNKNOWN": result["count"] for result in results}
        
        return severity_counts
        
    except Exception as e:
        logger.error(f"Error getting severity breakdown: {e}")
        return {}
@app.get("/api/debug/mongodb")
async def debug_mongodb():
    """Debug endpoint to check MongoDB connection and collections"""
    try:
        mongodb_manager = get_mongodb_manager()
        
        debug_info = {
            "connected": mongodb_manager.is_connected(),
            "database": mongodb_manager.database_name,
            "collections": {}
        }
        
        if mongodb_manager.is_connected():
            # Get collection stats
            collections = [
                ("anomalies", mongodb_manager.anomalies_collection),
                ("logs", mongodb_manager.logs_collection),
                ("users", mongodb_manager.users_collection)
            ]
            
            for name, collection in collections:
                try:
                    count = collection.count_documents({})
                    debug_info["collections"][name] = {
                        "count": count,
                        "sample_documents": list(collection.find().limit(2))
                    }
                except Exception as e:
                    debug_info["collections"][name] = {"error": str(e)}
        
        return debug_info
        
    except Exception as e:
        return {"error": f"Failed to connect to MongoDB: {e}"}

@app.get("/api/debug/raw-anomalies")
async def debug_raw_anomalies():
    """Debug endpoint to see raw anomaly data from MongoDB"""
    try:
        # Get recent anomalies from MongoDB
        anomalies = get_anomalies(limit=10)
        return {"mongodb_anomalies": anomalies}
        
    except Exception as e:
        logger.error(f"Error retrieving raw anomalies: {e}")
        return {"error": str(e)}


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(1)  # Send update every 30 seconds
            stats = calculate_system_stats()
            await websocket.send_json({
                "type": "stats_update",
                "data": stats.dict()
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task to monitor for new anomalies
async def monitor_anomalies():
    """Background task to monitor for new anomalies and broadcast updates"""
    last_anomaly_count = 0
    
    while True:
        try:
            current_anomalies = get_all_anomalies()
            current_count = len(current_anomalies)
            
            if current_count > last_anomaly_count:
                # New anomalies detected
                new_anomalies = current_anomalies[:current_count - last_anomaly_count]
                
                for anomaly in new_anomalies:
                    await manager.broadcast({
                        "type": "new_anomaly",
                        "data": anomaly
                    })
                
                last_anomaly_count = current_count
            
            await asyncio.sleep(1)  # Check every 5 seconds
            
        except Exception as e:
            logger.error(f"Error in anomaly monitoring: {e}")
            await asyncio.sleep(1)

# Lifespan handler is defined above with the FastAPI app

# Serve static files (React build) - only if directory exists
import os
if os.path.exists("frontend/build/static"):
    app.mount("/static", StaticFiles(directory="frontend/build/static"), name="static")
else:
    logger.warning("Frontend build directory not found. Static files will not be served.")

@app.get("/")
async def serve_dashboard():
    """Serve the main dashboard"""
    return FileResponse("frontend/index.html")

@app.get("/{full_path:path}")
async def serve_static_files(full_path: str):
    """Serve static files or redirect to dashboard"""
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    
    # For any other route, serve the dashboard
    return FileResponse("frontend/index.html")

if __name__ == "__main__":
    # Ensure output directory exists
    os.makedirs("../output", exist_ok=True)
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
