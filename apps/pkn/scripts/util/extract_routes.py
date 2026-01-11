#!/usr/bin/env python3
"""
Extract routes from divinenode_server.py and create blueprint files
"""

import re
from pathlib import Path
from collections import defaultdict


def extract_routes():
    """Extract all routes from divinenode_server.py"""
    server_file = Path(__file__).parent.parent.parent / "divinenode_server.py"
    content = server_file.read_text()

    # Find all route definitions
    routes = []
    lines = content.split("\n")

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("@app.route("):
            # Extract route decorator and function
            route_match = re.match(r"@app\.route\('([^']+)'.*\)", line)
            if route_match:
                route_path = route_match.group(1)
                # Skip static file routes
                if route_path in ["/", "/pkn.html", "/<path:filename>"]:
                    i += 1
                    continue

                # Find function definition
                i += 1
                func_line = lines[i]
                func_match = re.match(r"def (\w+)\(.*\):", func_line)
                if func_match:
                    func_name = func_match.group(1)

                    # Extract function body
                    i += 1
                    func_body = []
                    indent_level = None

                    while i < len(lines):
                        if indent_level is None and lines[i].strip():
                            # Determine indentation level from first non-empty line
                            indent_level = len(lines[i]) - len(lines[i].lstrip())

                        # Check if we've reached next decorator or function
                        if lines[i].startswith("@app.route") or (
                            lines[i].startswith("def ")
                            and not lines[i].startswith("    ")
                        ):
                            break

                        # Check if we're back at module level (no indentation)
                        if lines[i] and not lines[i][0].isspace() and lines[i].strip():
                            break

                        func_body.append(lines[i])
                        i += 1

                    routes.append(
                        {
                            "path": route_path,
                            "decorator": line,
                            "name": func_name,
                            "body": "\n".join(func_body),
                        }
                    )
                    continue
        i += 1

    # Group routes by category
    grouped = defaultdict(list)
    for route in routes:
        path = route["path"]
        if "/health" in path:
            grouped["health"].append(route)
        elif "/phonescan" in path:
            grouped["phonescan"].append(route)
        elif "/api/network" in path:
            grouped["network"].append(route)
        elif "/api/osint" in path:
            grouped["osint"].append(route)
        elif "/api/files" in path:
            grouped["files"].append(route)
        elif "/api/editor" in path:
            grouped["editor"].append(route)
        elif "/generate-image" in path:
            grouped["images"].append(route)
        elif "/api/models" in path:
            grouped["models"].append(route)
        elif "/api/chat" in path or "/api/agent" in path or "/api/autocomplete" in path:
            grouped["chat"].append(route)
        elif "/api/code" in path:
            grouped["code"].append(route)
        elif "/api/multi-agent" in path:
            grouped["multi_agent"].append(route)
        elif "/api/rag" in path:
            grouped["rag"].append(route)
        elif "/api/planning" in path:
            grouped["planning"].append(route)
        elif "/api/delegation" in path:
            grouped["delegation"].append(route)
        elif "/api/sandbox" in path:
            grouped["sandbox"].append(route)
        elif "/api/metrics" in path:
            grouped["metrics"].append(route)
        elif "/api/session" in path:
            grouped["session"].append(route)
        else:
            grouped["other"].append(route)

    # Print summary
    print("Routes grouped:")
    for category, routes in grouped.items():
        print(f"  {category}: {len(routes)} routes")

    return grouped


if __name__ == "__main__":
    routes = extract_routes()
    print(f"\nTotal route groups: {len(routes)}")
