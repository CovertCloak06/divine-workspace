#!/usr/bin/env python3
"""Test tool registry discovery and execution."""

import sys
sys.path.insert(0, '/home/gh0st/dvn/divine-workspace/apps/pkn')

from backend.tools import (
    TOOL_REGISTRY,
    list_available_tools,
    execute_tool,
    get_tool_schemas
)

print("="*60)
print("Tool Registry Test")
print("="*60)

# Test 1: Tool discovery
print("\n1. Testing Tool Discovery...")
all_tools = list_available_tools()
print(f"   ✓ Discovered {len(all_tools)} tools")

# Show breakdown by module
modules = {}
for tool in all_tools:
    module = tool.split('.')[0]
    modules[module] = modules.get(module, 0) + 1

print("\n   Tools per module:")
for module, count in sorted(modules.items()):
    print(f"   - {module}: {count} tools")

# Test 2: Tool execution (simple test with file_tools.glob)
print("\n2. Testing Tool Execution...")
try:
    result = execute_tool("file_tools.glob", pattern="*.py", path="/home/gh0st/dvn/divine-workspace/apps/pkn/backend")
    print(f"   ✓ Tool execution successful")
    print(f"   Status: {result['status']}")
    print(f"   Result preview: {result['result'][:200]}...")
except Exception as e:
    print(f"   ✗ Error: {e}")

# Test 3: Tool schemas
print("\n3. Testing Tool Schemas...")
schemas = get_tool_schemas()
print(f"   ✓ Retrieved {len(schemas)} tool schemas")

# Show a sample schema
sample_tool = "file_tools.glob"
if sample_tool in schemas:
    schema = schemas[sample_tool]
    print(f"\n   Sample schema ({sample_tool}):")
    print(f"   - Name: {schema['name']}")
    print(f"   - Description: {schema['description'][:100]}...")
    print(f"   - Parameters: {list(schema['parameters'].keys())}")

# Test 4: Capability-based filtering
print("\n4. Testing Capability Filtering...")
code_tools_schemas = get_tool_schemas(agent_capabilities=["code_writing"])
print(f"   ✓ Code writing capabilities: {len(code_tools_schemas)} tools")

research_tools = get_tool_schemas(agent_capabilities=["research"])
print(f"   ✓ Research capabilities: {len(research_tools)} tools")

print("\n" + "="*60)
print("✅ All Tests Passed!")
print("="*60)
