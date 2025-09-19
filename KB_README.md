# 🧠 Pathway Knowledge Base (KB) Module

## Overview

The Pathway Knowledge Base module provides RAG (Retrieval-Augmented Generation) capabilities for the cybersecurity anomaly detection system. It stores user profiles, anomaly history, and provides contextual information to enhance LLM explanations.

## Features

- **User Profile Management**: Bounded history of user activities (logins, file transfers)
- **Anomaly Storage**: Indexed storage of anomaly summaries with features
- **RAG Context Generation**: Privacy-preserving context for LLM explanations
- **Vector Database Integration**: Optional semantic search capabilities
- **Privacy Protection**: Automatic PII masking and sanitization

## Configuration

### Environment Variables

```bash
# Knowledge Base Configuration
KB_ENABLE_RAG=true                    # Enable RAG context generation
KB_CONTEXT_MAX_ITEMS=5               # Maximum items in context
KB_PII_EXPORT=false                  # Allow PII in vector DB exports

# Vector Database Configuration
VECTOR_DB_BACKEND=chroma             # chroma, pinecone, or none
VECTOR_DB_URL=                       # Vector DB connection URL
VECTOR_COLLECTION=anomalies          # Collection name for anomalies
```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `KB_ENABLE_RAG` | `true` | Enable RAG context generation for LLM |
| `KB_CONTEXT_MAX_ITEMS` | `5` | Maximum recent items to include in context |
| `KB_PII_EXPORT` | `false` | Allow PII in vector database exports |
| `VECTOR_DB_BACKEND` | `chroma` | Vector database backend (chroma/pinecone/none) |
| `VECTOR_DB_URL` | `""` | Vector database connection URL |
| `VECTOR_COLLECTION` | `anomalies` | Collection name for anomaly storage |

## Usage

### Basic Integration

The KB is automatically integrated into the anomaly detection pipeline:

```python
from pathway_kb import KB_INSTANCE

# User events are automatically upserted by detectors
# Anomalies are automatically stored by detectors
# Context is automatically retrieved for LLM explanations
```

### Manual Usage

```python
from pathway_kb import KB_INSTANCE

# Upsert user event
profile = KB_INSTANCE.upsert_user_event("username", {
    'location': 'New York',
    'timestamp': '2024-01-15T10:00:00',
    'ip_address': '192.168.1.100'
})

# Store anomaly
anomaly_id = KB_INSTANCE.upsert_anomaly({
    'type': 'login',
    'username': 'username',
    'severity': 'HIGH',
    'risk_score': 0.85
})

# Get context for LLM
context = KB_INSTANCE.get_context_for_anomaly(anomaly, max_items=5)
```

## Data Structures

### User Profile

```python
{
    'recent_logins': [              # Bounded to 20 entries
        {
            'location': 'New York',
            'timestamp': '2024-01-15T10:00:00',
            'ip_address': '192.168.1.100'
        }
    ],
    'normal_hours': [7, 8, 9, ...], # Normal login hours
    'file_stats': {
        'total_transfers': 10,
        'total_size_mb': 250.5,
        'avg_size_mb': 25.05,
        'max_size_mb': 100.0,
        'recent_files': [...]        # Bounded to 10 entries
    },
    'last_seen': '2024-01-15T10:00:00'
}
```

### Anomaly Summary

```python
{
    'anomaly_id': 'abc123def456',
    'type': 'login',
    'timestamp': '2024-01-15T10:00:00',
    'severity': 'HIGH',
    'username': 'username',
    'summary': 'Login from suspicious location',
    'features': {
        'type': 'login',
        'severity': 'HIGH',
        'risk_score': 0.85,
        'location': 'Moscow',
        'hour': 10
    }
}
```

### RAG Context

```python
{
    'masked_username': 'j***',
    'last_logins': [
        {
            'location': 'New York',
            'timestamp': '2024-01-15T10:00:00',
            'ip_masked': '192.168.xxx.xxx'
        }
    ],
    'normal_hours': [7, 8, 9, ...],
    'file_summary': {
        'total_transfers': 10,
        'avg_size_mb': 25.05,
        'max_size_mb': 100.0
    },
    'recent_related_anomalies': [...],
    'similar_anomalies': [...]
}
```

## Privacy Protection

### Automatic Masking

- **Usernames**: `john.doe` → `j***`
- **IP Addresses**: `192.168.1.100` → `192.168.xxx.xxx`
- **Filenames**: `sensitive_data.zip` → `***.zip`

### PII Export Control

By default, PII is never exported to vector databases. Set `KB_PII_EXPORT=true` to allow (not recommended for production).

## Vector Database Integration

### Chroma (Default)

```bash
pip install chromadb
```

```python
# Automatically initialized if chromadb is installed
VECTOR_DB_BACKEND=chroma
```

### Pinecone

```bash
pip install pinecone-client
```

```bash
export PINECONE_API_KEY=your_api_key
export PINECONE_ENV=your_environment
VECTOR_DB_BACKEND=pinecone
VECTOR_COLLECTION=anomalies
```

### Disable Vector DB

```bash
VECTOR_DB_BACKEND=none
# or
KB_ENABLE_RAG=false
```

## RAG Context Format

The KB generates compact context strings for LLM prompts:

```
CONTEXT (redacted): User j***; last_logins: [New York@01-15 10:00, Seattle@01-14 15:30]; normal_hours: 07-21; file_summary: 5 transfers, avg 25.5MB; recent_related: [Large file 01-18, login-new-ip 01-12]; Similar: Previous login from suspicious location, Large file transfer pattern
```

## Metrics

The KB tracks operational metrics:

```python
metrics = KB_INSTANCE.get_metrics()
# {
#     'kb_upserts': 150,
#     'kb_queries': 45,
#     'vector_exports': 120,
#     'vector_queries': 8
# }
```

## Error Handling

All KB operations are designed to fail gracefully:

- **KB failures**: Logged as warnings, system continues
- **Vector DB failures**: Logged as warnings, falls back to in-memory similarity
- **Context retrieval failures**: Returns empty context, LLM uses template explanation

## Testing

Run the test suite:

```bash
python -m pytest tests/test_pathway_kb.py -v
python -m pytest tests/test_integration_kb_alert.py -v
```

Run the demo:

```bash
python demo_kb_flow.py
```

## Performance Considerations

- **Bounded History**: User profiles are automatically bounded (20 logins, 10 files)
- **Anomaly Index**: Recent anomalies index is bounded to 500 entries
- **Context Size**: RAG context is limited to ~250 tokens
- **Lazy Loading**: Vector DB is initialized only when needed
- **Graceful Degradation**: System works without vector DB or external dependencies

## Security Notes

- **No PII by Default**: All PII is masked unless explicitly configured
- **Local Fallback**: System works without external vector DB services
- **Audit Trail**: All operations are logged for security monitoring
- **Token Limits**: Context strings are bounded to prevent prompt injection

## Troubleshooting

### Common Issues

1. **Vector DB Connection Failed**
   ```
   Solution: Check API keys and network connectivity
   Fallback: System continues with in-memory similarity
   ```

2. **KB Context Empty**
   ```
   Solution: Check if user has sufficient history
   Fallback: LLM uses template explanation
   ```

3. **Import Errors**
   ```
   Solution: Install missing dependencies (chromadb, pinecone-client)
   Fallback: System works without vector DB features
   ```

### Debug Logging

Enable debug logging to see KB operations:

```python
import logging
logging.getLogger('pathway_kb').setLevel(logging.DEBUG)
```

## Future Enhancements

- **Multi-tenant Support**: Separate KB instances per organization
- **Advanced Vector Search**: Hybrid search with keyword + semantic
- **Context Compression**: More sophisticated context summarization
- **Real-time Updates**: WebSocket-based context streaming
- **Analytics Dashboard**: KB metrics and performance monitoring
