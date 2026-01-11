"""
Web Tools - Internet Research and Data Retrieval
Enhanced version of web_tools.py with langchain integration.

Tools:
- web_search: DuckDuckGo search (privacy-focused)
- fetch_url: Get webpage content
- wiki_lookup: Wikipedia articles
- github_search: Find GitHub repositories
- stack_overflow_search: Search Stack Overflow
- docs_search: Search library documentation
"""

import requests
import json
from bs4 import BeautifulSoup
import html2text
from typing import Optional
from langchain_core.tools import tool

# Search engine layer (Termux-safe)
try:
    from ddg3 import DuckDuckGoSearch as DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except Exception:
        class DDGS:
            """Fallback for offline mode"""
            def text(self, query, max_results=5):
                return [{
                    "title": f"Offline: '{query}'",
                    "href": "#",
                    "body": "Search unavailable (no network)"
                }]

try:
    import wikipediaapi
except ImportError:
    wikipediaapi = None


@tool
def web_search(query: str, max_results: int = 5) -> str:
    """
    Search the web using DuckDuckGo (privacy-focused).

    Args:
        query: Search query
        max_results: Number of results to return (default: 5)

    Returns:
        JSON string with list of {title, url, snippet}

    Examples:
        web_search("Flask SSE example")
        web_search("Termux Python setup", max_results=10)

    Use this when you need:
        - Current information
        - Code examples
        - Documentation
        - Tutorials
        - Recent news/updates
    """
    try:
        with DDGS() as ddgs:
            results = []
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    'title': r.get('title', ''),
                    'url': r.get('href', ''),
                    'snippet': r.get('body', '')
                })
            return json.dumps({'query': query, 'results': results}, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'query': query})


@tool
def fetch_url(url: str, extract_text: bool = True) -> str:
    """
    Fetch and extract content from a URL.

    Converts HTML to readable markdown format.

    Args:
        url: URL to fetch
        extract_text: If True, convert HTML to text (default: True)

    Returns:
        JSON with {url, title, content}

    Examples:
        fetch_url("https://flask.palletsprojects.com/")
        fetch_url("https://docs.python.org/3/library/asyncio.html")

    Use this to:
        - Read documentation
        - Get blog post content
        - Extract text from web pages
    """
    try:
        headers = {
            'User-Agent': 'PKN-Agent/1.0 (Educational AI assistant)'
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else 'No title'

        if extract_text:
            # Remove unwanted tags
            for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                tag.decompose()

            # Convert to markdown
            h2t = html2text.HTML2Text()
            h2t.ignore_links = False
            content = h2t.handle(str(soup))
        else:
            content = response.text

        return json.dumps({
            'url': url,
            'title': title,
            'content': content[:15000],  # Limit to 15k chars
            'status': 'success'
        }, indent=2)

    except Exception as e:
        return json.dumps({
            'url': url,
            'error': str(e),
            'status': 'failed'
        })


@tool
def wiki_lookup(topic: str) -> str:
    """
    Look up a topic on Wikipedia.

    Args:
        topic: Topic to search for

    Returns:
        JSON with {title, summary, url}

    Examples:
        wiki_lookup("Python programming language")
        wiki_lookup("Termux")

    Use this for:
        - Quick factual lookups
        - Topic overviews
        - Historical information
        - Scientific/technical definitions
    """
    if wikipediaapi is None:
        return json.dumps({
            'error': 'wikipediaapi not installed',
            'install': 'pip install wikipedia-api'
        })

    try:
        wiki = wikipediaapi.Wikipedia('PKN-Agent/1.0', 'en')
        page = wiki.page(topic)

        if page.exists():
            return json.dumps({
                'title': page.title,
                'summary': page.summary[:3000],  # First 3k chars
                'url': page.fullurl,
                'status': 'success'
            }, indent=2)
        else:
            return json.dumps({
                'topic': topic,
                'error': 'Page not found',
                'status': 'not_found'
            })

    except Exception as e:
        return json.dumps({
            'topic': topic,
            'error': str(e),
            'status': 'failed'
        })


@tool
def github_search(query: str, max_results: int = 5) -> str:
    """
    Search GitHub repositories.

    Args:
        query: Search query
        max_results: Number of results (default: 5)

    Returns:
        JSON with list of {name, url, description, stars, language}

    Examples:
        github_search("Flask SSE")
        github_search("llama.cpp Android")

    Use this to:
        - Find code examples
        - Discover libraries
        - See implementation patterns
        - Check repository popularity
    """
    try:
        api_url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page={max_results}"
        headers = {'Accept': 'application/vnd.github.v3+json'}
        response = requests.get(api_url, headers=headers, timeout=15)
        response.raise_for_status()

        data = response.json()
        results = []
        for repo in data.get('items', []):
            results.append({
                'name': repo['full_name'],
                'url': repo['html_url'],
                'description': repo['description'] or 'No description',
                'stars': repo['stargazers_count'],
                'language': repo['language'] or 'Unknown'
            })

        return json.dumps({
            'query': query,
            'results': results
        }, indent=2)

    except Exception as e:
        return json.dumps({'error': str(e), 'query': query})


@tool
def stack_overflow_search(query: str, max_results: int = 5) -> str:
    """
    Search Stack Overflow questions and answers.

    Args:
        query: Search query
        max_results: Number of results (default: 5)

    Returns:
        JSON with list of {title, url, score, answered}

    Examples:
        stack_overflow_search("Flask asyncio")
        stack_overflow_search("Python subprocess timeout")

    Use this for:
        - Finding solutions to specific problems
        - Understanding error messages
        - Best practices
        - Common pitfalls
    """
    try:
        api_url = "https://api.stackexchange.com/2.3/search/advanced"
        params = {
            'order': 'desc',
            'sort': 'relevance',
            'q': query,
            'site': 'stackoverflow',
            'pagesize': max_results
        }
        response = requests.get(api_url, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()
        results = []
        for item in data.get('items', []):
            results.append({
                'title': item.get('title'),
                'url': item.get('link'),
                'score': item.get('score'),
                'answered': item.get('is_answered', False),
                'views': item.get('view_count', 0)
            })

        return json.dumps({
            'query': query,
            'results': results
        }, indent=2)

    except Exception as e:
        return json.dumps({'error': str(e), 'query': query})


@tool
def docs_search(library: str, query: str) -> str:
    """
    Search official documentation for popular libraries.

    Args:
        library: Library name (e.g., "python", "flask", "react")
        query: What to search for

    Returns:
        Suggested documentation URLs

    Examples:
        docs_search("python", "asyncio")
        docs_search("flask", "server-sent events")

    Supported libraries:
        - python, flask, django, fastapi
        - javascript, react, vue, nodejs
        - And many more via web search
    """
    docs_urls = {
        'python': 'https://docs.python.org/3',
        'flask': 'https://flask.palletsprojects.com',
        'django': 'https://docs.djangoproject.com',
        'fastapi': 'https://fastapi.tiangolo.com',
        'react': 'https://react.dev',
        'vue': 'https://vuejs.org',
        'nodejs': 'https://nodejs.org/docs',
        'numpy': 'https://numpy.org/doc',
        'pandas': 'https://pandas.pydata.org/docs',
    }

    base_url = docs_urls.get(library.lower())

    if base_url:
        # Search within known docs
        search_query = f"site:{base_url} {query}"
        return web_search(search_query, max_results=3)
    else:
        # Generic documentation search
        search_query = f"{library} documentation {query}"
        return web_search(search_query, max_results=5)


# Export tools
TOOLS = [
    web_search,
    fetch_url,
    wiki_lookup,
    github_search,
    stack_overflow_search,
    docs_search
]

TOOL_DESCRIPTIONS = {
    'web_search': 'Search the web (DuckDuckGo)',
    'fetch_url': 'Get and extract content from URLs',
    'wiki_lookup': 'Wikipedia article summaries',
    'github_search': 'Find GitHub repositories',
    'stack_overflow_search': 'Search Stack Overflow Q&A',
    'docs_search': 'Search library documentation',
}
