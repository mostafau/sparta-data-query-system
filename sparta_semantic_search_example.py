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
