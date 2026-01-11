#!/usr/bin/env python3
"""
Detect CSS selectors and DOM IDs referenced in JS but not defined in HTML/CSS.
Catches issues like getElementById('foo') when #foo doesn't exist.
"""

import re
from pathlib import Path


def find_missing_selectors(project_dir):
    """Find selectors used in JS but not defined in HTML/CSS | ref:CLAUDE.md (Code Documentation Standard)"""

    project_path = Path(project_dir)

    # Extract all IDs and classes from HTML files | ref:pkn.html
    defined_ids = set()
    defined_classes = set()

    html_files = list(project_path.glob("*.html")) + list(
        project_path.glob("**/*.html")
    )
    for html_file in html_files:
        if "node_modules" in str(html_file):
            continue

        try:
            with open(html_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Find all id="foo" patterns
                defined_ids.update(re.findall(r'id=["\']([^"\']+)["\']', content))
                # Find all class="foo bar" patterns | Split on whitespace
                class_attrs = re.findall(r'class=["\']([^"\']+)["\']', content)
                for classes in class_attrs:
                    defined_classes.update(classes.split())
        except Exception as e:
            print(f"⚠️  Error reading {html_file}: {e}")

    # Extract classes from CSS files | ref:main.css, multi_agent.css, etc
    css_files = list(project_path.glob("css/*.css")) + list(project_path.glob("*.css"))
    for css_file in css_files:
        if ".min.css" in str(css_file):
            continue

        try:
            with open(css_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Find all .className selectors | Matches .foo, .foo-bar, etc
                defined_classes.update(re.findall(r"\.([a-zA-Z][\w-]*)", content))
                # Find all #idName selectors
                defined_ids.update(re.findall(r"#([a-zA-Z][\w-]*)", content))
        except Exception as e:
            print(f"⚠️  Error reading {css_file}: {e}")

    # Extract selectors referenced in JavaScript | ref:app.js, js/*.js
    js_files = list(project_path.glob("*.js")) + list(project_path.glob("js/*.js"))

    used_ids = {}  # id_name -> [(file, line_num)]
    used_classes = {}  # class_name -> [(file, line_num)]

    for js_file in js_files:
        if "node_modules" in str(js_file) or ".min.js" in str(js_file):
            continue

        file_rel = str(js_file.relative_to(project_path))

        try:
            with open(js_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    # Find getElementById('foo') calls
                    id_matches = re.findall(
                        r'getElementById\(["\']([^"\']+)["\']\)', line
                    )
                    for id_name in id_matches:
                        if id_name not in used_ids:
                            used_ids[id_name] = []
                        used_ids[id_name].append((file_rel, line_num))

                    # Find querySelector('#foo') and querySelectorAll('#foo')
                    qs_id_matches = re.findall(
                        r'querySelector(?:All)?\(["\']#([^"\']+)["\']\)', line
                    )
                    for id_name in qs_id_matches:
                        if id_name not in used_ids:
                            used_ids[id_name] = []
                        used_ids[id_name].append((file_rel, line_num))

                    # Find classList operations: classList.add('foo'), classList.contains('foo')
                    class_matches = re.findall(
                        r'classList\.(?:add|remove|toggle|contains)\(["\']([^"\']+)["\']\)',
                        line,
                    )
                    for class_name in class_matches:
                        if class_name not in used_classes:
                            used_classes[class_name] = []
                        used_classes[class_name].append((file_rel, line_num))

                    # Find querySelector('.foo') and querySelectorAll('.foo')
                    qs_class_matches = re.findall(
                        r'querySelector(?:All)?\(["\']\.([^"\']+)["\']\)', line
                    )
                    for class_name in qs_class_matches:
                        if class_name not in used_classes:
                            used_classes[class_name] = []
                        used_classes[class_name].append((file_rel, line_num))

        except Exception as e:
            print(f"⚠️  Error reading {js_file}: {e}")

    # Find missing IDs and classes | Used in JS but not defined in HTML/CSS
    missing_ids = {
        id_name: locations
        for id_name, locations in used_ids.items()
        if id_name not in defined_ids
    }

    missing_classes = {
        class_name: locations
        for class_name, locations in used_classes.items()
        if class_name not in defined_classes
    }

    has_issues = False

    if missing_ids:
        has_issues = True
        print("❌ MISSING IDS:")
        print("=" * 60)
        for id_name, locations in sorted(missing_ids.items()):
            print(f"\n🔴 ID not found: #{id_name}")
            print(f"   Used in JavaScript:")
            for file_path, line_num in locations:
                print(f"      - {file_path}:{line_num}")

    if missing_classes:
        has_issues = True
        print("\n❌ MISSING CLASSES:")
        print("=" * 60)
        for class_name, locations in sorted(missing_classes.items()):
            print(f"\n🔴 Class not found: .{class_name}")
            print(f"   Used in JavaScript:")
            for file_path, line_num in locations:
                print(f"      - {file_path}:{line_num}")

    if has_issues:
        print("\n⚠️  Missing selectors cause runtime errors (element is null).")
        print("   Consider: Add missing elements to HTML or remove dead JS code.\n")
        return False
    else:
        print("✅ All selectors found in HTML/CSS")
        return True


if __name__ == "__main__":
    import sys

    project_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/gh0st/pkn"
    success = find_missing_selectors(project_dir)
    sys.exit(0 if success else 1)
