# SPARTA Space Cyber Security Data Extraction and Query System

This project extracts space cyber attack techniques and tactics from the SPARTA (Space Attack Research & Tactic Analysis) framework and provides tools for querying, searching, and fine-tuning language models on this domain-specific data.

## Overview

SPARTA is a framework developed by The Aerospace Corporation that provides unclassified information to space professionals about how spacecraft may be compromised via cyber and traditional counterspace means. This project:

1. **Extracts** all techniques and sub-techniques from the 9 SPARTA tactics
2. **Stores** data in structured JSON format for database integration
3. **Provides** keyword-based search functionality
4. **Enables** semantic search using sentence transformers
5. **Generates** training data for fine-tuning language models

## SPARTA Tactics (9 Categories)

| ID | Tactic | Description |
|----|--------|-------------|
| ST0001 | Reconnaissance | Gathering information about space systems |
| ST0002 | Resource Development | Establishing resources for operations |
| ST0003 | Initial Access | Gaining initial entry to space systems |
| ST0004 | Execution | Running malicious code on spacecraft |
| ST0005 | Persistence | Maintaining access to spacecraft |
| ST0006 | Defense Evasion | Avoiding detection |
| ST0007 | Lateral Movement | Moving through space system environments |
| ST0008 | Exfiltration | Stealing data from space systems |
| ST0009 | Impact | Manipulating, interrupting, or destroying space systems |

## Files Included

### Core Scripts

- **`sparta_extractor.py`** - Main data extraction script with keyword search
- **`sparta_semantic_search.py`** - Advanced semantic search using embeddings
- **`sparta_finetune.py`** - Training data generation and model fine-tuning

### Generated Data Files

- **`sparta_database.json`** - Complete database of 216 techniques/sub-techniques
- **`sparta_training_data.json`** - 1,755 instruction-tuning examples
- **`sparta_conversations.json`** - Conversation format for chat models
- **`sparta_corpus.json`** - Retrieval corpus for RAG systems

## Installation

```bash
# Basic functionality (keyword search)
pip install --break-system-packages -q numpy

# Semantic search
pip install --break-system-packages sentence-transformers torch

# Fine-tuning (requires GPU)
pip install --break-system-packages transformers peft datasets accelerate
```

## Usage

### 1. Basic Keyword Search

```python
from sparta_extractor import build_database, search_techniques

# Build the database
database = build_database()

# Search for techniques
results = search_techniques(database, "jamming satellite", top_k=5)
for r in results:
    print(f"[{r['id']}] {r['name']}: {r['description'][:100]}...")
```

### 2. Interactive Query Mode

```bash
# Run interactive keyword search
python sparta_extractor.py
```

### 3. Semantic Search (requires sentence-transformers)

```python
from sparta_semantic_search import SPARTASemanticSearch, SPARTAQueryAgent

# Initialize
search_engine = SPARTASemanticSearch()
search_engine.load_database()
search_engine.load_model()
search_engine.create_embeddings()

# Search
results = search_engine.search("How can attackers jam satellite communications?")
for entry, score in results:
    print(f"{score:.2%}: {entry['name']}")
```

### 4. Generate Training Data

```bash
# Generate all training data formats
python sparta_finetune.py
```

### 5. Fine-Tune a Model (requires GPU)

```bash
# Generate data and fine-tune
python sparta_finetune.py --train
```

## Database Schema

Each entry in `sparta_database.json` follows this structure:

```json
{
  "type": "technique|sub_technique",
  "id": "REC-0001",
  "name": "Gather Spacecraft Design Information",
  "description": "Threat actors may gather information...",
  "tactic": "Reconnaissance",
  "tactic_id": "ST0001",
  "tactic_description": "Threat actor is trying to gather information...",
  "parent_id": null,
  "parent_name": null,
  "full_text": "combined searchable text"
}
```

## Training Data Formats

### 1. Instruction Tuning Format (`sparta_training_data.json`)

```json
{
  "instruction": "What is Jamming?",
  "input": "",
  "output": "Jamming (EX-0016) is a technique under the Execution tactic...",
  "context": "Original description",
  "technique_id": "EX-0016"
}
```

### 2. Conversation Format (`sparta_conversations.json`)

```json
{
  "conversations": [
    {"role": "user", "content": "What is Jamming?"},
    {"role": "assistant", "content": "Jamming (EX-0016) is..."}
  ],
  "metadata": {"technique_id": "EX-0016", "domain": "space_security"}
}
```

### 3. Retrieval Corpus (`sparta_corpus.json`)

```json
{
  "id": "EX-0016",
  "title": "Jamming",
  "text": "Jamming is an electronic attack...",
  "metadata": {"type": "technique", "tactic": "Execution"}
}
```

## Statistics

- **Total Entries**: 216
- **Techniques**: 85
- **Sub-techniques**: 131
- **Training Examples**: 1,755

### By Tactic:

| Tactic | Techniques | Sub-techniques |
|--------|------------|----------------|
| Reconnaissance | 9 | 27 |
| Resource Development | 5 | 15 |
| Initial Access | 13 | 16 |
| Execution | 18 | 41 |
| Persistence | 5 | 2 |
| Defense Evasion | 12 | 20 |
| Lateral Movement | 7 | 1 |
| Exfiltration | 10 | 9 |
| Impact | 6 | 0 |

## Example Queries

The system can answer questions like:

- "How can an attacker jam satellite communications?"
- "What are supply chain attack methods for spacecraft?"
- "How can threat actors maintain persistence on a satellite?"
- "What physical attacks can damage satellites?"
- "How can hackers steal data from spacecraft?"
- "What reconnaissance techniques are used against space systems?"

## Integration with Databases

The JSON data can be easily imported into various databases:

```python
# SQLite
import sqlite3
import json

conn = sqlite3.connect('sparta.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE techniques (
        id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT,
        type TEXT,
        tactic TEXT,
        tactic_id TEXT
    )
''')

with open('sparta_database.json') as f:
    data = json.load(f)
    for entry in data:
        cursor.execute('''
            INSERT INTO techniques VALUES (?, ?, ?, ?, ?, ?)
        ''', (entry['id'], entry['name'], entry['description'], 
              entry['type'], entry['tactic'], entry['tactic_id']))

conn.commit()
```

## References

- SPARTA Website: https://sparta.aerospace.org/
- MITRE ATT&CK (inspiration): https://attack.mitre.org/
- The Aerospace Corporation: https://aerospace.org/

## License

This project extracts publicly available data from SPARTA. Please refer to The Aerospace Corporation's terms of use for the original SPARTA content.
