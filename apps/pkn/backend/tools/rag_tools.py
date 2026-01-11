#!/usr/bin/env python3
"""
RAG (Retrieval Augmented Generation) Tools
Semantic search over codebase for enhanced agent context
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import hashlib

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    print("Warning: chromadb not installed. Run: pip install chromadb")

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    print("Warning: sentence-transformers not installed. Run: pip install sentence-transformers")


class RAGMemory:
    """
    Semantic memory for code and documentation retrieval.
    Uses ChromaDB for vector storage and sentence-transformers for embeddings.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.chroma_path = self.project_root / ".chroma_db"
        self.chroma_path.mkdir(exist_ok=True)

        self.available = CHROMA_AVAILABLE and SENTENCE_TRANSFORMERS_AVAILABLE

        if not CHROMA_AVAILABLE:
            self.client = None
            self.code_collection = None
            self.docs_collection = None
            self.conversation_collection = None
            self.encoder = None
            return

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.chroma_path),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

        # Collections for different content types
        self.code_collection = self._get_or_create_collection("code_memory")
        self.docs_collection = self._get_or_create_collection("docs_memory")
        self.conversation_collection = self._get_or_create_collection("conversation_memory")

        # Load embedding model (small and fast)
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        else:
            self.encoder = None
            print("Warning: Using ChromaDB default embeddings (slower)")

    def _get_or_create_collection(self, name: str):
        """Get or create a ChromaDB collection"""
        try:
            return self.client.get_collection(name)
        except:
            return self.client.create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )

    def _get_file_hash(self, filepath: Path) -> str:
        """Get MD5 hash of file for change detection"""
        return hashlib.md5(filepath.read_bytes()).hexdigest()

    def index_file(self, filepath: Path, collection_name: str = "code"):
        """Index a single file into the appropriate collection"""

        if not filepath.exists():
            return {"error": f"File not found: {filepath}"}

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            return {"error": f"Could not read file: {e}"}

        # Skip empty or very small files
        if len(content.strip()) < 50:
            return {"skipped": "File too small"}

        # Select collection
        collection = self.code_collection if collection_name == "code" else self.docs_collection

        # Create chunks for large files (every 500 lines)
        lines = content.split('\n')
        chunks = []

        if len(lines) > 500:
            for i in range(0, len(lines), 500):
                chunk = '\n'.join(lines[i:i+500])
                chunks.append({
                    'content': chunk,
                    'chunk_id': i // 500
                })
        else:
            chunks.append({
                'content': content,
                'chunk_id': 0
            })

        # Index each chunk
        file_hash = self._get_file_hash(filepath)
        indexed_count = 0

        for chunk in chunks:
            doc_id = f"{filepath}:chunk_{chunk['chunk_id']}"

            metadata = {
                "file": str(filepath),
                "file_hash": file_hash,
                "chunk_id": chunk['chunk_id'],
                "file_type": filepath.suffix,
                "total_chunks": len(chunks)
            }

            try:
                collection.add(
                    documents=[chunk['content']],
                    metadatas=[metadata],
                    ids=[doc_id]
                )
                indexed_count += 1
            except Exception as e:
                # Document might already exist, try updating
                try:
                    collection.update(
                        documents=[chunk['content']],
                        metadatas=[metadata],
                        ids=[doc_id]
                    )
                    indexed_count += 1
                except:
                    pass

        return {
            "success": True,
            "file": str(filepath),
            "chunks_indexed": indexed_count
        }

    def index_codebase(self, extensions: List[str] = ['.py', '.js', '.html', '.css', '.sh', '.md']):
        """Index all code files in the project"""

        results = {
            'indexed': [],
            'errors': [],
            'skipped': []
        }

        for ext in extensions:
            for filepath in self.project_root.rglob(f"*{ext}"):
                # Skip hidden directories and build artifacts
                if any(part.startswith('.') for part in filepath.parts):
                    if '.chroma_db' not in str(filepath) and '.venv' not in str(filepath):
                        continue

                # Skip large directories
                if any(skip in str(filepath) for skip in ['node_modules', '__pycache__', 'build', '.git']):
                    continue

                result = self.index_file(
                    filepath,
                    collection_name="docs" if ext == '.md' else "code"
                )

                if result.get('success'):
                    results['indexed'].append(str(filepath))
                elif result.get('error'):
                    results['errors'].append({
                        'file': str(filepath),
                        'error': result['error']
                    })
                else:
                    results['skipped'].append(str(filepath))

        return results

    def search_code(self, query: str, n_results: int = 5, file_type: Optional[str] = None) -> Dict[str, Any]:
        """Search codebase for relevant snippets"""

        where_filter = None
        if file_type:
            where_filter = {"file_type": file_type}

        try:
            results = self.code_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_filter
            )

            # Format results
            formatted = []
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i]
                formatted.append({
                    'content': doc,
                    'file': metadata['file'],
                    'chunk_id': metadata.get('chunk_id', 0),
                    'relevance_score': 1.0 - results['distances'][0][i] if 'distances' in results else None
                })

            return {
                'success': True,
                'results': formatted,
                'query': query
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def search_docs(self, query: str, n_results: int = 3) -> Dict[str, Any]:
        """Search documentation for relevant info"""

        try:
            results = self.docs_collection.query(
                query_texts=[query],
                n_results=n_results
            )

            formatted = []
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i]
                formatted.append({
                    'content': doc,
                    'file': metadata['file'],
                    'relevance_score': 1.0 - results['distances'][0][i] if 'distances' in results else None
                })

            return {
                'success': True,
                'results': formatted,
                'query': query
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def add_conversation_memory(self, session_id: str, user_message: str,
                                agent_response: str, agent_type: str):
        """Store important conversation exchanges for future reference"""

        # Create searchable document from exchange
        doc = f"""User: {user_message}
Agent ({agent_type}): {agent_response}"""

        doc_id = f"conv_{session_id}_{int(time.time())}"

        try:
            self.conversation_collection.add(
                documents=[doc],
                metadatas=[{
                    'session_id': session_id,
                    'agent_type': agent_type,
                    'timestamp': time.time()
                }],
                ids=[doc_id]
            )
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def search_conversation_history(self, query: str, n_results: int = 5) -> Dict[str, Any]:
        """Search past conversations for relevant context"""

        try:
            results = self.conversation_collection.query(
                query_texts=[query],
                n_results=n_results
            )

            formatted = []
            for i, doc in enumerate(results['documents'][0]):
                metadata = results['metadatas'][0][i]
                formatted.append({
                    'content': doc,
                    'session_id': metadata['session_id'],
                    'agent_type': metadata['agent_type'],
                    'timestamp': metadata.get('timestamp'),
                    'relevance_score': 1.0 - results['distances'][0][i] if 'distances' in results else None
                })

            return {
                'success': True,
                'results': formatted,
                'query': query
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about indexed content"""

        return {
            'code_documents': self.code_collection.count(),
            'doc_documents': self.docs_collection.count(),
            'conversation_documents': self.conversation_collection.count(),
            'storage_path': str(self.chroma_path)
        }

    def reset(self, collection_name: Optional[str] = None):
        """Reset a collection or all collections"""

        if collection_name:
            try:
                self.client.delete_collection(collection_name)
                if collection_name == "code_memory":
                    self.code_collection = self._get_or_create_collection("code_memory")
                elif collection_name == "docs_memory":
                    self.docs_collection = self._get_or_create_collection("docs_memory")
                elif collection_name == "conversation_memory":
                    self.conversation_collection = self._get_or_create_collection("conversation_memory")
                return {'success': True, 'message': f'Reset {collection_name}'}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            # Reset all
            try:
                self.client.reset()
                self.code_collection = self._get_or_create_collection("code_memory")
                self.docs_collection = self._get_or_create_collection("docs_memory")
                self.conversation_collection = self._get_or_create_collection("conversation_memory")
                return {'success': True, 'message': 'Reset all collections'}
            except Exception as e:
                return {'success': False, 'error': str(e)}


# Convenience functions for use in agent_manager
def search_relevant_code(query: str, project_root: str = "/home/gh0st/pkn", n_results: int = 5):
    """Quick function to search for relevant code"""
    rag = RAGMemory(project_root)
    return rag.search_code(query, n_results)


def search_relevant_docs(query: str, project_root: str = "/home/gh0st/pkn", n_results: int = 3):
    """Quick function to search for relevant documentation"""
    rag = RAGMemory(project_root)
    return rag.search_docs(query, n_results)


if __name__ == "__main__":
    import time

    # Test RAG system
    print("Testing RAG Memory System...")

    rag = RAGMemory()

    print("\n1. Indexing codebase...")
    start = time.time()
    results = rag.index_codebase()
    duration = time.time() - start

    print(f"   Indexed: {len(results['indexed'])} files")
    print(f"   Errors: {len(results['errors'])}")
    print(f"   Skipped: {len(results['skipped'])}")
    print(f"   Time: {duration:.2f}s")

    print("\n2. Testing code search...")
    search_result = rag.search_code("multi-agent coordination", n_results=3)
    if search_result['success']:
        print(f"   Found {len(search_result['results'])} results:")
        for i, result in enumerate(search_result['results'][:2], 1):
            print(f"   {i}. {result['file']} (score: {result['relevance_score']:.3f})")

    print("\n3. Testing doc search...")
    doc_result = rag.search_docs("how to start the server", n_results=2)
    if doc_result['success']:
        print(f"   Found {len(doc_result['results'])} results:")
        for i, result in enumerate(doc_result['results'], 1):
            print(f"   {i}. {result['file']} (score: {result['relevance_score']:.3f})")

    print("\n4. Statistics:")
    stats = rag.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n✓ RAG system test complete!")
