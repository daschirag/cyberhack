"""
LLM Service for generating cybersecurity explanations
Uses OpenAI GPT models to create contextual anomaly explanations
"""

import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI

from .config import RAGConfig

logger = logging.getLogger(__name__)

class LLMService:
    """OpenAI-based LLM service for generating cybersecurity explanations"""
    
    def __init__(self):
        if not RAGConfig.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required")
        self.client = OpenAI(
            api_key=RAGConfig.OPENAI_API_KEY
        )
    
    def generate_anomaly_explanation(
        self, 
        anomaly: Dict[str, Any], 
        context_documents: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate comprehensive explanation for cybersecurity anomaly"""
        
        try:
            # Build context from retrieved documents
            context_text = self._build_context_text(context_documents)
            
            # Create prompt for the specific anomaly type
            prompt = self._create_anomaly_prompt(anomaly, context_text)
            
            # Generate explanation using OpenAI
            response = self.client.chat.completions.create(
                model=RAGConfig.OPENAI_MODEL,
                messages=[
                    {
                        "role": "system", 
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=RAGConfig.LLM_TEMPERATURE,
                max_tokens=RAGConfig.MAX_TOKENS
            )
            
            explanation_text = response.choices[0].message.content.strip()
            
            # Parse the explanation into structured format
            parsed_explanation = self._parse_explanation(explanation_text)
            
            # Generate recommended actions
            actions = self._generate_recommended_actions(anomaly, context_documents)
            
            return {
                "ai_explanation": explanation_text,
                "structured_explanation": parsed_explanation,
                "recommended_actions": actions,
                "context_sources": [doc.get("metadata", {}).get("filename", "Unknown") 
                                  for doc in context_documents],
                "confidence_score": self._calculate_confidence(anomaly, context_documents)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return {
                "ai_explanation": f"Error generating explanation: {str(e)}",
                "recommended_actions": self._get_default_actions(anomaly),
                "context_sources": [],
                "confidence_score": 0.0
            }
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for cybersecurity analyst"""
        return """You are a senior cybersecurity analyst with expertise in threat detection and incident response. 
        Your role is to analyze security anomalies and provide clear, actionable explanations to help security teams respond effectively.
        
        Always structure your response with:
        1. WHY - Why this is suspicious or risky
        2. SEVERITY - Risk level assessment (Low/Medium/High/Critical)
        3. CONTEXT - Relevant threat intelligence or attack patterns
        4. IMPACT - Potential business or security impact
        
        Be concise, technical but accessible, and focus on actionable insights."""
    
    def _create_anomaly_prompt(self, anomaly: Dict[str, Any], context_text: str) -> str:
        """Create specific prompt for anomaly analysis"""
        
        anomaly_type = anomaly.get("type", "unknown")
        
        base_prompt = f"""
        Analyze this cybersecurity anomaly:
        
        ANOMALY DETAILS:
        Type: {anomaly_type}
        Severity: {anomaly.get('severity', 'Unknown')}
        Risk Score: {anomaly.get('risk_score', 'Unknown')}
        Timestamp: {anomaly.get('timestamp', 'Unknown')}
        """
        
        # Add type-specific details
        if anomaly_type == "login_anomaly":
            base_prompt += f"""
            User: {anomaly.get('username', 'Unknown')}
            Location: {anomaly.get('location', 'Unknown')}
            IP Address: {anomaly.get('ip_address', 'Unknown')}
            Detected Issues: {anomaly.get('anomalies', [])}
            """
            
        elif anomaly_type == "network_anomaly":
            base_prompt += f"""
            Requests per minute: {anomaly.get('requests_per_minute', 'Unknown')}
            Baseline: {anomaly.get('baseline', 'Unknown')}
            Spike ratio: {anomaly.get('spike_ratio', 'Unknown')}
            Source IP: {anomaly.get('source_ip', 'Unknown')}
            """
            
        elif anomaly_type == "file_anomaly":
            base_prompt += f"""
            User: {anomaly.get('username', 'Unknown')}
            File size: {anomaly.get('file_size_mb', 'Unknown')} MB
            Operation: {anomaly.get('operation', 'Unknown')}
            Filename: {anomaly.get('filename', 'Unknown')}
            Detected Issues: {anomaly.get('anomalies', [])}
            """
        
        base_prompt += f"""
        
        RELEVANT THREAT INTELLIGENCE:
        {context_text}
        
        Provide a comprehensive analysis following the WHY, SEVERITY, CONTEXT, IMPACT structure.
        Keep the response under 300 words and focus on actionable insights.
        """
        
        return base_prompt
    
    def _build_context_text(self, context_documents: List[Dict[str, Any]]) -> str:
        """Build context text from retrieved documents"""
        if not context_documents:
            return "No relevant threat intelligence found."
        
        context_parts = []
        for i, doc in enumerate(context_documents[:RAGConfig.MAX_CONTEXT_ITEMS], 1):
            source = doc.get("metadata", {}).get("filename", "Unknown")
            text = doc.get("text", "")[:500]  # Limit text length
            context_parts.append(f"{i}. Source: {source}\n{text}")
        
        return "\n\n".join(context_parts)
    
    def _parse_explanation(self, explanation_text: str) -> Dict[str, str]:
        """Parse explanation text into structured format"""
        sections = {
            "why": "",
            "severity": "",
            "context": "",
            "impact": ""
        }
        
        current_section = None
        lines = explanation_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.upper().startswith('WHY'):
                current_section = "why"
                sections[current_section] = line
            elif line.upper().startswith('SEVERITY'):
                current_section = "severity"
                sections[current_section] = line
            elif line.upper().startswith('CONTEXT'):
                current_section = "context"
                sections[current_section] = line
            elif line.upper().startswith('IMPACT'):
                current_section = "impact"
                sections[current_section] = line
            elif current_section and line:
                sections[current_section] += f" {line}"
        
        return sections
    
    def _generate_recommended_actions(
        self, 
        anomaly: Dict[str, Any], 
        context_documents: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommended actions based on anomaly type and context"""
        
        anomaly_type = anomaly.get("type", "")
        severity = anomaly.get("severity", "MEDIUM")
        
        actions = []
        
        if "login" in anomaly_type:
            actions = [
                "Block suspicious IP address",
                "Force password reset for affected user",
                "Enable multi-factor authentication",
                "Review user's recent activities"
            ]
            if severity == "CRITICAL":
                actions.extend([
                    "Immediately disable user account",
                    "Notify security team for investigation"
                ])
                
        elif "network" in anomaly_type:
            actions = [
                "Enable rate limiting on affected services",
                "Monitor traffic patterns for escalation",
                "Activate WAF challenge mode",
                "Check for DDoS mitigation triggers"
            ]
            if severity in ["HIGH", "CRITICAL"]:
                actions.extend([
                    "Contact upstream providers for filtering",
                    "Implement emergency geo-blocking"
                ])
                
        elif "file" in anomaly_type:
            actions = [
                "Quarantine affected endpoint",
                "Revoke user access tokens",
                "Preserve audit logs",
                "Notify data protection team"
            ]
            if severity == "CRITICAL":
                actions.extend([
                    "Initiate incident response procedure",
                    "Consider legal notification requirements"
                ])
        
        # Add context-specific actions from knowledge base
        for doc in context_documents:
            text = doc.get("text", "").lower()
            if "mitigation" in text or "action" in text:
                # Extract action items from context (simplified)
                if "mfa" in text or "multi-factor" in text:
                    actions.append("Implement multi-factor authentication")
                if "block" in text and "ip" in text:
                    actions.append("Consider IP blocking rules")
        
        # Remove duplicates while preserving order
        unique_actions = []
        for action in actions:
            if action not in unique_actions:
                unique_actions.append(action)
        
        return unique_actions[:6]  # Limit to 6 actions
    
    def _calculate_confidence(
        self, 
        anomaly: Dict[str, Any], 
        context_documents: List[Dict[str, Any]]
    ) -> float:
        """Calculate confidence score for the explanation"""
        
        base_confidence = 0.5
        
        # Increase confidence based on available context
        if context_documents:
            base_confidence += 0.2 * min(len(context_documents), 3) / 3
        
        # Increase confidence based on anomaly completeness
        if anomaly.get("risk_score", 0) > 0:
            base_confidence += 0.1
        
        if anomaly.get("severity"):
            base_confidence += 0.1
        
        if anomaly.get("timestamp"):
            base_confidence += 0.05
        
        return min(base_confidence, 1.0)
    
    def _get_default_actions(self, anomaly: Dict[str, Any]) -> List[str]:
        """Get default actions when explanation generation fails"""
        anomaly_type = anomaly.get("type", "")
        
        if "login" in anomaly_type:
            return ["Review login details", "Verify user identity", "Check for unusual activity"]
        elif "network" in anomaly_type:
            return ["Monitor network traffic", "Check for attack patterns", "Review security logs"]
        elif "file" in anomaly_type:
            return ["Review file access logs", "Check for data exfiltration", "Verify user permissions"]
        else:
            return ["Investigate anomaly details", "Review security policies", "Document incident"]
