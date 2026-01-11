#!/usr/bin/env python3
"""
Code Context System for Autocomplete
Analyzes code files to extract symbols, imports, and provide intelligent completions
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict


class CodeContext:
    """
    Maintains code context for intelligent autocomplete.
    Supports Python, JavaScript, HTML, CSS, and common web formats.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.recent_files = []
        self.symbols = defaultdict(list)  # {file_path: [symbols]}
        self.imports = defaultdict(list)  # {file_path: [imports]}
        self.file_cache = {}  # {file_path: {analyzed_at, content_hash}}

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a file and extract symbols, imports, and structure.
        Returns: {symbols: [...], imports: [...], language: str}
        """
        path = Path(file_path)
        if not path.exists():
            return {'error': 'File not found', 'symbols': [], 'imports': []}

        # Determine language by extension
        ext = path.suffix.lower()
        language = self._detect_language(ext)

        try:
            content = path.read_text(encoding='utf-8')
        except Exception as e:
            return {'error': str(e), 'symbols': [], 'imports': []}

        # Analyze based on language
        if language == 'python':
            return self._analyze_python(content, file_path)
        elif language == 'javascript':
            return self._analyze_javascript(content, file_path)
        elif language == 'html':
            return self._analyze_html(content, file_path)
        elif language == 'css':
            return self._analyze_css(content, file_path)
        else:
            return {'language': language, 'symbols': [], 'imports': []}

    def _detect_language(self, ext: str) -> str:
        """Detect programming language from file extension"""
        mapping = {
            '.py': 'python',
            '.js': 'javascript',
            '.mjs': 'javascript',
            '.ts': 'typescript',
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown',
            '.sh': 'bash',
        }
        return mapping.get(ext, 'text')

    def _analyze_python(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract Python symbols: functions, classes, imports"""
        symbols = []
        imports = []

        # Extract imports
        import_patterns = [
            r'^import\s+(\w+)',
            r'^from\s+([\w.]+)\s+import\s+([\w,\s]+)',
        ]
        for pattern in import_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                imports.append(match.group(0))

        # Extract function definitions
        func_pattern = r'^def\s+(\w+)\s*\((.*?)\):'
        for match in re.finditer(func_pattern, content, re.MULTILINE):
            name = match.group(1)
            params = match.group(2)
            symbols.append({
                'name': name,
                'type': 'function',
                'signature': f"def {name}({params}):",
                'line': content[:match.start()].count('\n') + 1
            })

        # Extract class definitions
        class_pattern = r'^class\s+(\w+)(?:\((.*?)\))?:'
        for match in re.finditer(class_pattern, content, re.MULTILINE):
            name = match.group(1)
            bases = match.group(2) or ''
            symbols.append({
                'name': name,
                'type': 'class',
                'signature': f"class {name}({bases}):" if bases else f"class {name}:",
                'line': content[:match.start()].count('\n') + 1
            })

        # Extract variables (simple assignments at module level)
        var_pattern = r'^([A-Z_][A-Z0-9_]*)\s*='
        for match in re.finditer(var_pattern, content, re.MULTILINE):
            name = match.group(1)
            symbols.append({
                'name': name,
                'type': 'constant',
                'line': content[:match.start()].count('\n') + 1
            })

        # Cache results
        self.symbols[file_path] = symbols
        self.imports[file_path] = imports

        return {
            'language': 'python',
            'symbols': symbols,
            'imports': imports,
            'file_path': file_path
        }

    def _analyze_javascript(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract JavaScript symbols: functions, classes, variables"""
        symbols = []
        imports = []

        # Extract imports (ES6 modules)
        import_patterns = [
            r'import\s+.*?from\s+[\'"].*?[\'"]',
            r'import\s+[\'"].*?[\'"]',
            r'require\([\'"].*?[\'"]\)',
        ]
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                imports.append(match.group(0))

        # Extract function declarations
        func_patterns = [
            r'function\s+(\w+)\s*\((.*?)\)',
            r'const\s+(\w+)\s*=\s*\((.*?)\)\s*=>',
            r'(\w+)\s*:\s*function\s*\((.*?)\)',
            r'async\s+function\s+(\w+)\s*\((.*?)\)',
        ]
        for pattern in func_patterns:
            for match in re.finditer(pattern, content):
                name = match.group(1)
                params = match.group(2) if len(match.groups()) > 1 else ''
                symbols.append({
                    'name': name,
                    'type': 'function',
                    'signature': f"{name}({params})",
                    'line': content[:match.start()].count('\n') + 1
                })

        # Extract class definitions
        class_pattern = r'class\s+(\w+)(?:\s+extends\s+(\w+))?'
        for match in re.finditer(class_pattern, content):
            name = match.group(1)
            extends = match.group(2)
            symbols.append({
                'name': name,
                'type': 'class',
                'extends': extends,
                'line': content[:match.start()].count('\n') + 1
            })

        # Extract const/let/var declarations
        var_pattern = r'(?:const|let|var)\s+(\w+)\s*='
        for match in re.finditer(var_pattern, content):
            name = match.group(1)
            symbols.append({
                'name': name,
                'type': 'variable',
                'line': content[:match.start()].count('\n') + 1
            })

        self.symbols[file_path] = symbols
        self.imports[file_path] = imports

        return {
            'language': 'javascript',
            'symbols': symbols,
            'imports': imports,
            'file_path': file_path
        }

    def _analyze_html(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract HTML elements and IDs"""
        symbols = []

        # Extract IDs
        id_pattern = r'id=[\'"](\w+)[\'"]'
        for match in re.finditer(id_pattern, content):
            symbols.append({
                'name': match.group(1),
                'type': 'id',
                'selector': f"#{match.group(1)}"
            })

        # Extract classes
        class_pattern = r'class=[\'"]([^"\']+)[\'"]'
        for match in re.finditer(class_pattern, content):
            classes = match.group(1).split()
            for cls in classes:
                symbols.append({
                    'name': cls,
                    'type': 'class',
                    'selector': f".{cls}"
                })

        self.symbols[file_path] = symbols

        return {
            'language': 'html',
            'symbols': symbols,
            'imports': [],
            'file_path': file_path
        }

    def _analyze_css(self, content: str, file_path: str) -> Dict[str, Any]:
        """Extract CSS selectors and classes"""
        symbols = []

        # Extract class selectors
        class_pattern = r'\.([a-zA-Z0-9_-]+)\s*\{'
        for match in re.finditer(class_pattern, content):
            symbols.append({
                'name': match.group(1),
                'type': 'class',
                'selector': f".{match.group(1)}"
            })

        # Extract ID selectors
        id_pattern = r'#([a-zA-Z0-9_-]+)\s*\{'
        for match in re.finditer(id_pattern, content):
            symbols.append({
                'name': match.group(1),
                'type': 'id',
                'selector': f"#{match.group(1)}"
            })

        self.symbols[file_path] = symbols

        return {
            'language': 'css',
            'symbols': symbols,
            'imports': [],
            'file_path': file_path
        }

    def get_completions(self, prefix: str, file_path: str = '', context_line: str = '') -> List[Dict[str, Any]]:
        """
        Get autocomplete suggestions based on prefix and context.

        Args:
            prefix: The partial text to complete
            file_path: Current file being edited
            context_line: The full line of code for context

        Returns:
            List of completion suggestions with metadata
        """
        completions = []

        # If we have a file path, analyze it first
        if file_path and Path(file_path).exists():
            self.analyze_file(file_path)

        # Gather symbols from current file
        if file_path in self.symbols:
            for symbol in self.symbols[file_path]:
                if symbol['name'].startswith(prefix):
                    completions.append({
                        'text': symbol['name'],
                        'type': symbol['type'],
                        'source': 'current_file',
                        'detail': symbol.get('signature', ''),
                    })

        # Gather symbols from all analyzed files (project-wide)
        for path, symbols in self.symbols.items():
            if path != file_path:  # Skip current file (already added)
                for symbol in symbols:
                    if symbol['name'].startswith(prefix):
                        completions.append({
                            'text': symbol['name'],
                            'type': symbol['type'],
                            'source': Path(path).name,
                            'detail': symbol.get('signature', ''),
                        })

        # Add common language keywords
        if file_path.endswith('.py'):
            keywords = ['def', 'class', 'import', 'from', 'if', 'else', 'elif', 'for', 'while',
                       'try', 'except', 'finally', 'with', 'as', 'return', 'yield', 'async', 'await']
            for kw in keywords:
                if kw.startswith(prefix):
                    completions.append({
                        'text': kw,
                        'type': 'keyword',
                        'source': 'python',
                        'detail': 'Python keyword'
                    })
        elif file_path.endswith('.js'):
            keywords = ['function', 'const', 'let', 'var', 'class', 'if', 'else', 'for', 'while',
                       'return', 'async', 'await', 'import', 'export', 'from', 'default']
            for kw in keywords:
                if kw.startswith(prefix):
                    completions.append({
                        'text': kw,
                        'type': 'keyword',
                        'source': 'javascript',
                        'detail': 'JavaScript keyword'
                    })

        # Remove duplicates and sort by relevance
        seen = set()
        unique_completions = []
        for comp in completions:
            if comp['text'] not in seen:
                seen.add(comp['text'])
                unique_completions.append(comp)

        # Sort: current file first, then by type, then alphabetically
        unique_completions.sort(key=lambda x: (
            0 if x['source'] == 'current_file' else 1,
            x['type'],
            x['text']
        ))

        return unique_completions[:20]  # Limit to 20 suggestions

    def get_signature(self, symbol_name: str, file_path: str = '') -> Optional[str]:
        """Get the signature/definition of a symbol"""
        # Search in current file first
        if file_path in self.symbols:
            for symbol in self.symbols[file_path]:
                if symbol['name'] == symbol_name:
                    return symbol.get('signature', symbol['name'])

        # Search in all files
        for path, symbols in self.symbols.items():
            for symbol in symbols:
                if symbol['name'] == symbol_name:
                    return symbol.get('signature', symbol['name'])

        return None

    def scan_project(self, extensions: List[str] = ['.py', '.js', '.html', '.css']) -> Dict[str, int]:
        """
        Scan entire project and build symbol index.
        Returns: {language: file_count}
        """
        stats = defaultdict(int)

        for ext in extensions:
            pattern = f"**/*{ext}"
            for file_path in self.project_root.glob(pattern):
                # Skip hidden directories and common excludes
                if any(part.startswith('.') for part in file_path.parts):
                    continue
                if any(excl in str(file_path) for excl in ['node_modules', '__pycache__', 'venv']):
                    continue

                try:
                    result = self.analyze_file(str(file_path))
                    stats[result.get('language', 'unknown')] += 1
                except Exception:
                    continue

        return dict(stats)

    def get_project_stats(self) -> Dict[str, Any]:
        """Get statistics about analyzed code"""
        return {
            'files_analyzed': len(self.symbols),
            'total_symbols': sum(len(syms) for syms in self.symbols.values()),
            'files_by_type': {
                'python': sum(1 for f in self.symbols if f.endswith('.py')),
                'javascript': sum(1 for f in self.symbols if f.endswith('.js')),
                'html': sum(1 for f in self.symbols if f.endswith('.html')),
                'css': sum(1 for f in self.symbols if f.endswith('.css')),
            }
        }


# Global instance for API use
code_context = CodeContext()


if __name__ == '__main__':
    # Test the code context system
    ctx = CodeContext()

    print("Scanning project...")
    stats = ctx.scan_project()
    print(f"Scanned: {stats}")

    print("\nProject stats:")
    print(json.dumps(ctx.get_project_stats(), indent=2))

    # Test completions
    print("\nTesting completions for 'get':")
    completions = ctx.get_completions('get', file_path='/home/gh0st/pkn/code_context.py')
    for comp in completions[:10]:
        print(f"  - {comp['text']} ({comp['type']}) from {comp['source']}")
