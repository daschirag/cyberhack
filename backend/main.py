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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define lifespan handler first
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    # Startup
    asyncio.create_task(monitor_anomalies())
    logger.info("Anomaly monitoring started")
    yield
    # Shutdown (if needed)
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

# Utility functions
def read_jsonl_file(filepath: str) -> List[Dict]:
    """Read JSONL file and return list of anomalies"""
    anomalies = []
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        if 'anomaly' in data:
                            anomalies.append(data['anomaly'])
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
    return anomalies

def get_all_anomalies() -> List[Dict]:
    """Get all anomalies from output files"""
    all_anomalies = []
    
    # Read from all anomaly files
    anomaly_files = [
        "./output/login_anomalies.jsonl",
        "./output/network_anomalies.jsonl", 
        "./output/file_anomalies.jsonl"
    ]
    
    for filepath in anomaly_files:
        anomalies = read_jsonl_file(filepath)
        for anomaly in anomalies:
            # Add type information
            if 'location' in anomaly:
                anomaly['type'] = 'login'
            elif 'requests_per_minute' in anomaly:
                anomaly['type'] = 'network'
            elif 'file_size_mb' in anomaly:
                anomaly['type'] = 'file_transfer'
            else:
                anomaly['type'] = 'unknown'
            
            all_anomalies.append(anomaly)
    
    # Sort by timestamp (newest first)
    all_anomalies.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return all_anomalies

def calculate_system_stats() -> SystemStats:
    """Calculate system statistics"""
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
        system_uptime="2h 34m"  # This would be calculated from actual uptime
    )

# API Routes
@app.get("/")
async def root():
    return {"message": "Cybersecurity Anomaly Detection API", "status": "running"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/anomalies", response_model=List[AnomalyResponse])
async def get_anomalies(limit: int = 50, severity: Optional[str] = None):
    """Get recent anomalies with optional filtering"""
    anomalies = get_all_anomalies()
    
    if severity:
        anomalies = [a for a in anomalies if a.get('severity') == severity.upper()]
    
    # Limit results
    anomalies = anomalies[:limit]
    
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

@app.get("/api/stats", response_model=SystemStats)
async def get_system_stats():
    """Get system statistics"""
    return calculate_system_stats()

@app.get("/api/anomalies/recent")
async def get_recent_anomalies(hours: int = 1):
    """Get anomalies from the last N hours"""
    cutoff_time = datetime.now() - timedelta(hours=hours)
    anomalies = get_all_anomalies()
    
    recent_anomalies = []
    for anomaly in anomalies:
        try:
            anomaly_time = datetime.fromisoformat(anomaly.get('timestamp', '').replace('Z', '+00:00'))
            if anomaly_time >= cutoff_time:
                recent_anomalies.append(anomaly)
        except:
            continue
    
    return recent_anomalies

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
    """Get breakdown of anomaly types"""
    anomalies = get_all_anomalies()
    
    type_counts = {}
    for anomaly in anomalies:
        anomaly_type = anomaly.get('type', 'unknown')
        type_counts[anomaly_type] = type_counts.get(anomaly_type, 0) + 1
    
    return type_counts

@app.get("/api/anomalies/severity")
async def get_severity_breakdown():
    """Get severity level breakdown"""
    anomalies = get_all_anomalies()
    
    severity_counts = {}
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return severity_counts

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send periodic updates
            await asyncio.sleep(30)  # Send update every 30 seconds
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
            
            await asyncio.sleep(5)  # Check every 5 seconds
            
        except Exception as e:
            logger.error(f"Error in anomaly monitoring: {e}")
            await asyncio.sleep(10)

# Lifespan handler is defined above with the FastAPI app

# Serve static files (React build) - only if directory exists
import os
if os.path.exists("frontend/build/static"):
    app.mount("/static", StaticFiles(directory="frontend/build/static"), name="static")
else:
    logger.warning("Frontend build directory not found. Static files will not be served.")

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    """Serve React app for all non-API routes"""
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    
    # Serve index.html for all other routes (React Router)
    return FileResponse("frontend/build/index.html")

if __name__ == "__main__":
    # Ensure output directory exists
    os.makedirs("./output", exist_ok=True)
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
