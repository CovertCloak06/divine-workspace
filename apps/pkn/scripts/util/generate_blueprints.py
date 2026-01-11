#!/usr/bin/env python3
"""
Automated Blueprint Generator
Extracts all routes from divinenode_server.py and creates modular blueprint files
"""

import re
from pathlib import Path
from collections import defaultdict

# Route grouping patterns
ROUTE_GROUPS = {
    "health": [r"/health", r"/api/health"],
    "phonescan": [r"/api/phonescan"],
    "network": [r"/api/network/"],
    "osint": [r"/api/osint/"],
    "files": [r"/api/files/"],
    "editor": [r"/api/editor/"],
    "images": [r"/api/generate-image"],
    "models": [r"/api/models/"],
    "chat": [r"/api/chat", r"/api/agent", r"/api/autocomplete"],
    "code": [r"/api/code/"],
    "multi_agent": [r"/api/multi-agent/"],
    "rag": [r"/api/rag/"],
    "planning": [r"/api/planning/"],
    "delegation": [r"/api/delegation/"],
    "sandbox": [r"/api/sandbox/"],
    "metrics": [r"/api/metrics/"],
    "session": [r"/api/session/"],
}


def classify_route(route_path):
    """Determine which group a route belongs to"""
    for group, patterns in ROUTE_GROUPS.items():
        for pattern in patterns:
            if pattern in route_path:
                return group
    return "other"


def extract_function_body(lines, start_idx):
    """Extract complete function body including nested blocks"""
    body_lines = []
    indent_level = None
    i = start_idx

    while i < len(lines):
        line = lines[i]

        # Determine base indentation from first non-empty line
        if indent_level is None and line.strip() and not line.strip().startswith("#"):
            indent_level = len(line) - len(line.lstrip())

        # Check for next function/decorator at module level
        if line.startswith("@app.route") or (
            line.startswith("def ") and not line.startswith(" ")
        ):
            break

        # Check if we're back at module level
        if indent_level is not None and line.strip() and not line.startswith("#"):
            current_indent = len(line) - len(line.lstrip())
            if current_indent < indent_level and not line.strip().startswith(
                ("except", "elif", "else", "finally")
            ):
                break

        body_lines.append(line)
        i += 1

    return "\n".join(body_lines), i


def parse_routes(server_file_path):
    """Parse divinenode_server.py and extract all routes"""
    content = server_file_path.read_text()
    lines = content.split("\n")

    routes = defaultdict(list)
    imports_section = []
    helper_functions = []

    # Extract imports (first 60 lines)
    for i, line in enumerate(lines[:60]):
        if line.startswith(("import ", "from ")) or line.strip().startswith("import"):
            imports_section.append(line)

    # Extract helper functions and globals
    in_function = False
    for i, line in enumerate(lines):
        # Find _join_url and other helper functions
        if line.startswith("def _") and not line.startswith("def __"):
            body, end_idx = extract_function_body(lines, i + 1)
            helper_functions.append(f"{line}\n{body}")
        # Find OLLAMA_BASE, LOCAL_LLM_BASE globals
        if "OLLAMA_BASE" in line or "LOCAL_LLM_BASE" in line:
            helper_functions.append(line)

    # Extract routes
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("@app.route("):
            # Extract route decorator
            route_match = re.match(r"@app\.route\('([^']+)'[^)]*\)", line)
            if not route_match:
                i += 1
                continue

            route_path = route_match.group(1)

            # Skip static file routes
            if route_path in ["/", "/pkn.html", "/<path:filename>"]:
                i += 1
                continue

            # Get function definition
            i += 1
            if i >= len(lines):
                break

            func_line = lines[i]
            func_match = re.match(r"def (\w+)\(.*\):", func_line)
            if not func_match:
                continue

            func_name = func_match.group(1)

            # Extract function body
            body, end_idx = extract_function_body(lines, i + 1)

            # Classify route
            group = classify_route(route_path)

            routes[group].append(
                {
                    "decorator": line,
                    "function": func_line,
                    "body": body,
                    "name": func_name,
                    "path": route_path,
                }
            )

            i = end_idx
            continue

        i += 1

    return routes, imports_section, helper_functions


def generate_blueprint_file(group_name, routes, imports, helpers, output_dir):
    """Generate a blueprint file for a route group"""

    # Blueprint class name
    bp_var = f"{group_name}_bp"

    # Start building the file
    lines = [
        '"""',
        f"{group_name.title()} Routes Blueprint",
        f"Extracted from divinenode_server.py",
        '"""',
        "from flask import Blueprint, request, jsonify",
    ]

    # Add necessary imports based on route content
    all_content = "\n".join([r["body"] for r in routes])

    if "phonenumbers" in all_content:
        lines.append("import phonenumbers")
        lines.append("from phonenumbers import geocoder, carrier, timezone")
    if "subprocess" in all_content:
        lines.append("import subprocess")
    if "socket" in all_content:
        lines.append("import socket")
    if "json" in all_content:
        lines.append("import json")
    if "uuid" in all_content:
        lines.append("import uuid")
    if "requests" in all_content:
        lines.append("import requests")
    if "Path" in all_content:
        lines.append("from pathlib import Path")
    if "os.environ" in all_content or "os.path" in all_content:
        lines.append("import os")
    if "time" in all_content:
        lines.append("import time")
    if "local_image_gen" in all_content:
        lines.append("import local_image_gen")
    if "agent_manager" in all_content or "AgentManager" in all_content:
        lines.append("# TODO: Update import after agent_manager is split")
        lines.append("# from ..agents.manager import AgentManager")
    if "tools.osint_tools" in all_content or "OSINTTools" in all_content:
        lines.append("from tools.osint_tools import OSINTTools")

    lines.append("")

    # Add helper functions/globals if needed
    for helper in helpers:
        if helper.strip() in all_content:
            lines.append(helper)

    lines.append("")

    # Create blueprint
    lines.append(f"# Create blueprint")
    lines.append(f"{bp_var} = Blueprint('{group_name}', __name__)")
    lines.append("")

    # Add all routes
    for route in routes:
        lines.append(route["decorator"].replace("@app.route", f"@{bp_var}.route"))
        lines.append(route["function"])
        lines.append(route["body"])
        lines.append("")

    # Write file
    output_file = output_dir / f"{group_name}.py"
    output_file.write_text("\n".join(lines))
    print(f"✅ Created {output_file.name} ({len(routes)} routes, {len(lines)} lines)")

    return len(lines)


def main():
    """Main execution"""
    # Paths
    root = Path(__file__).parent.parent.parent
    server_file = root / "divinenode_server.py"
    output_dir = root / "backend" / "routes"

    print(f"📖 Parsing {server_file.name}...")
    routes, imports, helpers = parse_routes(server_file)

    print(
        f"\n📊 Found {sum(len(r) for r in routes.values())} routes in {len(routes)} groups"
    )
    for group, route_list in routes.items():
        print(f"  {group}: {len(route_list)} routes")

    print(f"\n🔨 Generating blueprint files in {output_dir}...")
    total_lines = 0

    for group, route_list in routes.items():
        if group == "other":
            print(
                f"⚠️  Skipping 'other' group - {len(route_list)} routes need manual classification"
            )
            continue
        lines = generate_blueprint_file(group, route_list, imports, helpers, output_dir)
        total_lines += lines

    print(f"\n✅ Generated {len(routes) - 1} blueprint files")
    print(
        f"📏 Total lines: {total_lines} (from original {sum(1 for _ in server_file.read_text().splitlines())} lines)"
    )
    print(
        f"✅ Average file size: {total_lines // (len(routes) - 1)} lines per blueprint"
    )


if __name__ == "__main__":
    main()
