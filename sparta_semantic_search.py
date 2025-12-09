#!/usr/bin/env python3
"""
SPARTA Advanced Semantic Search System
Uses sentence transformers for semantic similarity search on space cyber attack techniques.
"""

import json
import os
import pickle
import numpy as np
from typing import List, Dict, Tuple, Optional

# Check if required packages are available
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    print("Note: sentence-transformers not available. Install with: pip install sentence-transformers")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class SPARTASemanticSearch:
    """Semantic search engine for SPARTA space cyber attack techniques."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the semantic search engine.
        
        Args:
            model_name: Name of the sentence transformer model to use.
                       Options: 'all-MiniLM-L6-v2' (fast), 'all-mpnet-base-v2' (accurate)
        """
        self.model_name = model_name
        self.model = None
        self.database = None
        self.embeddings = None
        self.index_path = "sparta_embeddings.pkl"
        
    def load_model(self):
        """Load the sentence transformer model."""
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            raise ImportError("sentence-transformers package is required. Install with: pip install sentence-transformers")
        
        print(f"Loading model: {self.model_name}...")
        self.model = SentenceTransformer(self.model_name)
        print("Model loaded successfully!")
        
    def load_database(self, filename: str = "sparta_database.json"):
        """Load the SPARTA database from JSON file."""
        with open(filename, 'r', encoding='utf-8') as f:
            self.database = json.load(f)
        print(f"Loaded {len(self.database)} entries from database.")
        
    def create_embeddings(self):
        """Create embeddings for all database entries."""
        if self.model is None:
            self.load_model()
            
        if self.database is None:
            self.load_database()
        
        print("Creating embeddings for database entries...")
        
        # Create rich text representations for embedding
        texts = []
        for entry in self.database:
            # Combine various fields for richer semantic representation
            text_parts = [
                f"Technique: {entry['name']}",
                f"Description: {entry['description']}",
                f"Tactic: {entry['tactic']}",
                f"Category: {entry['type'].replace('_', ' ')}"
            ]
            if entry.get('parent_name'):
                text_parts.append(f"Parent: {entry['parent_name']}")
            
            text = ". ".join(text_parts)
            texts.append(text)
        
        # Generate embeddings
        self.embeddings = self.model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
        print(f"Created {len(self.embeddings)} embeddings with dimension {self.embeddings.shape[1]}")
        
    def save_embeddings(self):
        """Save embeddings to disk."""
        data = {
            'embeddings': self.embeddings,
            'model_name': self.model_name
        }
        with open(self.index_path, 'wb') as f:
            pickle.dump(data, f)
        print(f"Embeddings saved to {self.index_path}")
        
    def load_embeddings(self):
        """Load embeddings from disk."""
        if os.path.exists(self.index_path):
            with open(self.index_path, 'rb') as f:
                data = pickle.load(f)
            self.embeddings = data['embeddings']
            print(f"Loaded embeddings from {self.index_path}")
            return True
        return False
    
    def search(self, query: str, top_k: int = 5, min_score: float = 0.0) -> List[Tuple[Dict, float]]:
        """
        Search for techniques semantically similar to the query.
        
        Args:
            query: Search query
            top_k: Number of results to return
            min_score: Minimum similarity score (0-1)
            
        Returns:
            List of (entry, score) tuples sorted by relevance
        """
        if self.model is None:
            self.load_model()
            
        if self.embeddings is None:
            if not self.load_embeddings():
                self.create_embeddings()
                self.save_embeddings()
        
        # Encode query
        query_embedding = self.model.encode([query], convert_to_numpy=True)[0]
        
        # Calculate cosine similarities
        similarities = np.dot(self.embeddings, query_embedding) / (
            np.linalg.norm(self.embeddings, axis=1) * np.linalg.norm(query_embedding)
        )
        
        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        results = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score >= min_score:
                results.append((self.database[idx], score))
        
        return results
    
    def search_by_tactic(self, tactic_name: str) -> List[Dict]:
        """Get all techniques for a specific tactic."""
        if self.database is None:
            self.load_database()
            
        tactic_lower = tactic_name.lower()
        return [entry for entry in self.database if tactic_lower in entry['tactic'].lower()]
    
    def get_related_techniques(self, technique_id: str, top_k: int = 5) -> List[Tuple[Dict, float]]:
        """Find techniques related to a given technique ID."""
        if self.database is None:
            self.load_database()
            
        # Find the technique
        technique = None
        for entry in self.database:
            if entry['id'] == technique_id:
                technique = entry
                break
        
        if technique is None:
            return []
        
        # Search using the technique's description
        return self.search(technique['description'], top_k=top_k + 1)[1:]  # Exclude itself


class SPARTAQueryAgent:
    """
    An intelligent agent that can answer questions about space cyber security
    using the SPARTA database.
    """
    
    def __init__(self, search_engine: SPARTASemanticSearch):
        self.search_engine = search_engine
        
    def answer_query(self, query: str) -> str:
        """
        Answer a user query about space security.
        
        Args:
            query: User's question
            
        Returns:
            Formatted answer with relevant techniques
        """
        # Detect query type
        query_lower = query.lower()
        
        # Check if asking about a specific tactic
        tactic_keywords = {
            'reconnaissance': 'Reconnaissance',
            'resource development': 'Resource Development',
            'initial access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'defense evasion': 'Defense Evasion',
            'lateral movement': 'Lateral Movement',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        }
        
        for keyword, tactic in tactic_keywords.items():
            if keyword in query_lower:
                techniques = self.search_engine.search_by_tactic(tactic)
                return self._format_tactic_response(tactic, techniques)
        
        # General semantic search
        results = self.search_engine.search(query, top_k=5, min_score=0.3)
        return self._format_search_response(query, results)
    
    def _format_tactic_response(self, tactic: str, techniques: List[Dict]) -> str:
        """Format response for tactic-specific queries."""
        response = [f"\n### {tactic} Tactic\n"]
        
        main_techniques = [t for t in techniques if t['type'] == 'technique']
        sub_techniques = [t for t in techniques if t['type'] == 'sub_technique']
        
        response.append(f"Found {len(main_techniques)} techniques and {len(sub_techniques)} sub-techniques.\n")
        
        for tech in main_techniques:
            response.append(f"\n**{tech['id']}: {tech['name']}**")
            response.append(f"  {tech['description'][:200]}...")
            
            # Find sub-techniques
            subs = [s for s in sub_techniques if s.get('parent_id') == tech['id']]
            if subs:
                response.append("  Sub-techniques:")
                for sub in subs:
                    response.append(f"    - {sub['id']}: {sub['name']}")
        
        return "\n".join(response)
    
    def _format_search_response(self, query: str, results: List[Tuple[Dict, float]]) -> str:
        """Format response for semantic search queries."""
        if not results:
            return "No relevant techniques found for your query. Try rephrasing or using different keywords."
        
        response = [f"\n### Relevant Space Attack Techniques for: '{query}'\n"]
        
        for i, (entry, score) in enumerate(results, 1):
            response.append(f"\n**{i}. {entry['name']}** (ID: {entry['id']})")
            response.append(f"   Relevance Score: {score:.2%}")
            response.append(f"   Tactic: {entry['tactic']}")
            response.append(f"   Type: {entry['type'].replace('_', ' ').title()}")
            if entry.get('parent_name'):
                response.append(f"   Parent: {entry['parent_name']}")
            response.append(f"   Description: {entry['description']}")
        
        return "\n".join(response)


def setup_and_test():
    """Setup the search engine and run test queries."""
    print("="*80)
    print("SPARTA Semantic Search System Setup")
    print("="*80)
    
    # Initialize search engine
    search_engine = SPARTASemanticSearch(model_name="all-MiniLM-L6-v2")
    
    # Load database
    search_engine.load_database("sparta_database.json")
    
    # Create embeddings if not available
    if SENTENCE_TRANSFORMERS_AVAILABLE:
        search_engine.load_model()
        
        if not search_engine.load_embeddings():
            search_engine.create_embeddings()
            search_engine.save_embeddings()
        
        # Initialize query agent
        agent = SPARTAQueryAgent(search_engine)
        
        # Test queries
        test_queries = [
            "How can an attacker jam satellite communications?",
            "What are supply chain attack methods for spacecraft?",
            "How can threat actors maintain persistence on a satellite?",
            "What physical attacks can damage satellites?",
            "How can hackers steal data from spacecraft?",
            "What reconnaissance techniques are used against space systems?"
        ]
        
        print("\n" + "="*80)
        print("Test Queries")
        print("="*80)
        
        for query in test_queries:
            print(f"\n{'='*80}")
            print(f"QUERY: {query}")
            print("="*80)
            answer = agent.answer_query(query)
            print(answer)
    else:
        print("\nSentence Transformers not available.")
        print("The system will fall back to keyword-based search.")
        print("To enable semantic search, install: pip install sentence-transformers torch")


def interactive_mode():
    """Run interactive query mode."""
    print("\n" + "="*80)
    print("SPARTA Interactive Query Mode")
    print("="*80)
    
    search_engine = SPARTASemanticSearch()
    search_engine.load_database("sparta_database.json")
    
    if SENTENCE_TRANSFORMERS_AVAILABLE:
        search_engine.load_model()
        if not search_engine.load_embeddings():
            search_engine.create_embeddings()
            search_engine.save_embeddings()
        
        agent = SPARTAQueryAgent(search_engine)
        
        print("\nEnter your questions about space security (type 'quit' to exit)")
        print("Example queries:")
        print("  - How can attackers jam satellite signals?")
        print("  - What are the reconnaissance techniques?")
        print("  - Tell me about supply chain attacks on spacecraft")
        
        while True:
            print("\n")
            query = input("Your question: ").strip()
            
            if query.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not query:
                continue
            
            answer = agent.answer_query(query)
            print(answer)
    else:
        print("\nSemantic search requires sentence-transformers.")
        print("Falling back to basic search from sparta_extractor.py")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_mode()
    else:
        setup_and_test()
