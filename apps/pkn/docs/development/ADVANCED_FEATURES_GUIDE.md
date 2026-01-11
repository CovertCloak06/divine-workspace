# Advanced Agent Features - Integration Guide

This guide explains how to integrate the new Week 2-3 and Week 4 agent improvements into your PKN system.

## New Features Overview

### Week 2-3 Features
1. **RAG (Retrieval Augmented Generation)** - Semantic code search using ChromaDB
2. **Planning/Execution Separation** - Break complex tasks into structured plans
3. **Agent-to-Agent Delegation** - Agents can collaborate and delegate subtasks

### Week 4 Features
4. **Tool Chaining** - Execute sequences of tools with data flow
5. **Code Sandbox** - Safely execute code in Docker containers
6. **Agent Evaluation** - Track performance metrics and identify improvements

## Installation

### 1. Install New Dependencies

```bash
cd /home/gh0st/pkn
source .venv/bin/activate
pip install -r requirements.txt
```

This will install:
- `chromadb` - Vector database for RAG
- `sentence-transformers` - Embeddings for semantic search
- `docker` - Python Docker SDK for code sandbox

### 2. Install Docker (for Code Sandbox)

```bash
# Ubuntu/Debian
sudo apt-get install docker.io
sudo usermod -aG docker $USER
# Log out and back in for group changes

# Verify
docker --version
```

### 3. Index Your Codebase (RAG)

```bash
python3 -c "
from tools.rag_tools import RAGMemory
rag = RAGMemory()
print('Indexing codebase...')
results = rag.index_codebase()
print(f'Indexed: {len(results[\"indexed\"])} files')
"
```

## Integration into agent_manager.py

### Step 1: Add Imports

Add these imports at the top of `agent_manager.py`:

```python
# New advanced features
from tools.rag_tools import RAGMemory, search_relevant_code
from tools.planning_tools import TaskPlanner, PlanExecutor
from tools.delegation_tools import AgentDelegationManager
from tools.chain_tools import ToolChainExecutor
from tools.sandbox_tools import CodeSandbox
from tools.evaluation_tools import AgentEvaluator
```

### Step 2: Initialize in `AgentManager.__init__`

Add these to the `__init__` method:

```python
def __init__(self, project_root: str = "/home/gh0st/pkn"):
    # ... existing code ...

    # Advanced features
    self.rag_memory = RAGMemory(project_root)
    self.task_planner = TaskPlanner(self._llm_client, project_root)
    self.plan_executor = PlanExecutor(self)
    self.delegation_manager = AgentDelegationManager(self, project_root)
    self.tool_chain_executor = ToolChainExecutor(self._get_tool_registry())
    self.code_sandbox = CodeSandbox(project_root)
    self.evaluator = AgentEvaluator(project_root)
```

### Step 3: Create Tool Registry Helper

Add this method to `AgentManager`:

```python
def _get_tool_registry(self) -> Dict:
    """Get registry of available tools for tool chaining"""
    from tools import file_tools, code_tools, web_tools

    return {
        'file_tools.read_file': file_tools.read_file,
        'file_tools.write_file': file_tools.write_file,
        'file_tools.search_files': file_tools.search_files,
        'code_tools.analyze_code': code_tools.analyze_code,
        'web_tools.http_request': web_tools.http_request,
        # Add more as needed
    }
```

## Usage Examples

### 1. Using RAG for Context-Aware Responses

```python
# In agent_manager.py, enhance your execute_task method:

def execute_task_with_rag(self, agent_type, task, session_id):
    """Execute task with RAG-enhanced context"""

    # Search for relevant code
    code_results = self.rag_memory.search_code(task, n_results=3)

    # Build enhanced context
    context = {
        'relevant_code': code_results.get('results', []),
        'task': task
    }

    # Execute with context
    return self.execute_task(agent_type, task, session_id, context=context)
```

### 2. Using Planning for Complex Tasks

```python
def handle_complex_task(self, task, session_id):
    """Use planner for multi-step tasks"""

    # Create plan
    plan = self.task_planner.create_plan(task)

    print(f"Created plan with {len(plan.steps)} steps")
    for i, step in enumerate(plan.steps, 1):
        print(f"  {i}. {step.action} (agent: {step.agent_type})")

    # Execute plan
    result = self.plan_executor.execute_plan(plan, session_id)

    return result
```

### 3. Using Agent Delegation

```python
def coder_asks_researcher_for_help(self, task, session_id):
    """Example: Coder agent delegates research to Researcher agent"""

    # Coder realizes it needs documentation
    help_request = "Find documentation about Python asyncio best practices"

    # Delegate to researcher
    delegation_result = self.delegation_manager.request_help(
        requesting_agent='coder',
        help_needed=help_request,
        context={'original_task': task},
        task_id=session_id
    )

    # Execute delegation
    if delegation_result['success']:
        delegation_id = delegation_result['delegation_id']
        research_result = self.delegation_manager.execute_delegation(
            delegation_id, session_id
        )

        # Coder now has research context
        return research_result
```

### 4. Using Multi-Agent Collaboration

```python
def collaborate_on_task(self, task, session_id):
    """Multiple agents work together"""

    # Define which agents should collaborate
    agents_needed = ['reasoner', 'researcher', 'coder']

    # Let them collaborate
    result = self.delegation_manager.collaborate(
        agents=agents_needed,
        task=task,
        session_id=session_id,
        coordinator='reasoner'
    )

    return result['final_result']
```

### 5. Using Tool Chains

```python
def find_and_document_todos(self, session_id):
    """Example: Find all TODOs and create summary document"""

    # Create chain
    chain = self.tool_chain_executor.create_chain(
        name="todo_summary",
        description="Find TODOs and create summary"
    )

    # Set variables
    chain.variables = {
        'project_root': '/home/gh0st/pkn',
        'pattern': 'TODO'
    }

    # Add steps
    self.tool_chain_executor.add_tool_step(
        chain,
        tool_name='file_tools.search_files',
        parameters={'pattern': '*.py', 'path': '$project_root'},
        save_as='python_files'
    )

    self.tool_chain_executor.add_tool_step(
        chain,
        tool_name='file_tools.grep',
        parameters={'pattern': '$pattern', 'files': '$python_files'},
        save_as='todos'
    )

    self.tool_chain_executor.add_tool_step(
        chain,
        tool_name='file_tools.write_file',
        parameters={
            'path': '/home/gh0st/pkn/TODO_SUMMARY.md',
            'content': '$todos'
        },
        save_as='summary_file'
    )

    # Execute
    result = self.tool_chain_executor.execute_chain(chain)
    return result
```

### 6. Using Code Sandbox

```python
def test_generated_code(self, code, language='python'):
    """Safely test code in sandbox"""

    if language == 'python':
        result = self.code_sandbox.execute_python(code, timeout=30)
    elif language == 'javascript':
        result = self.code_sandbox.execute_javascript(code, timeout=30)

    if result['success']:
        return {
            'tested': True,
            'output': result['output'],
            'safe_to_use': True
        }
    else:
        return {
            'tested': True,
            'error': result['error'],
            'safe_to_use': False
        }
```

### 7. Using Agent Evaluation

```python
def log_and_evaluate(self, agent_type, task, response, duration_ms, success):
    """Log execution and track metrics"""

    # Log execution
    self.evaluator.log_execution(
        agent_type=agent_type,
        task=task,
        response=response,
        duration_ms=duration_ms,
        success=success,
        tools_used=self.last_tools_used,  # Track this in your code
        session_id=self.current_session_id
    )

    # Periodically check for improvements
    if self.execution_count % 100 == 0:
        suggestions = self.evaluator.generate_improvement_suggestions(agent_type)
        if suggestions:
            print(f"\n📊 Improvement suggestions for {agent_type}:")
            for sugg in suggestions[:3]:
                print(f"  • {sugg['issue']}")
```

## API Endpoints to Add

Add these routes to `divinenode_server.py`:

```python
@app.route('/api/multi-agent/plan', methods=['POST'])
def create_execution_plan():
    """Create an execution plan for a complex task"""
    data = request.get_json()
    task = data.get('task')

    plan = agent_manager.task_planner.create_plan(task)

    return jsonify({
        'success': True,
        'plan_id': plan.id,
        'goal': plan.goal,
        'steps': [step.to_dict() for step in plan.steps],
        'estimated_duration': plan.estimated_total_duration
    })


@app.route('/api/multi-agent/execute-plan', methods=['POST'])
def execute_plan():
    """Execute a created plan"""
    data = request.get_json()
    plan_id = data.get('plan_id')
    session_id = data.get('session_id', str(uuid.uuid4()))

    plan = agent_manager.task_planner.load_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    result = agent_manager.plan_executor.execute_plan(plan, session_id)

    return jsonify(result)


@app.route('/api/multi-agent/collaborate', methods=['POST'])
def multi_agent_collaborate():
    """Have multiple agents collaborate on a task"""
    data = request.get_json()
    task = data.get('task')
    agents = data.get('agents', ['reasoner', 'coder'])
    session_id = data.get('session_id', str(uuid.uuid4()))

    result = agent_manager.delegation_manager.collaborate(
        agents=agents,
        task=task,
        session_id=session_id
    )

    return jsonify(result)


@app.route('/api/sandbox/execute', methods=['POST'])
def execute_code_sandbox():
    """Execute code in sandbox"""
    data = request.get_json()
    code = data.get('code')
    language = data.get('language', 'python')

    if language == 'python':
        result = agent_manager.code_sandbox.execute_python(code)
    elif language == 'javascript':
        result = agent_manager.code_sandbox.execute_javascript(code)
    else:
        return jsonify({'error': f'Unsupported language: {language}'}), 400

    return jsonify(result)


@app.route('/api/metrics/agent/<agent_type>', methods=['GET'])
def get_agent_metrics(agent_type):
    """Get performance metrics for an agent"""
    days = request.args.get('days', 30, type=int)

    metrics = agent_manager.evaluator.get_agent_metrics(agent_type, days)

    return jsonify(metrics)


@app.route('/api/metrics/report', methods=['GET'])
def get_summary_report():
    """Get summary performance report"""
    days = request.args.get('days', 7, type=int)

    report = agent_manager.evaluator.get_summary_report(days)

    return jsonify({'report': report})


@app.route('/api/rag/search', methods=['POST'])
def search_codebase():
    """Search codebase with RAG"""
    data = request.get_json()
    query = data.get('query')
    n_results = data.get('n_results', 5)

    result = agent_manager.rag_memory.search_code(query, n_results)

    return jsonify(result)
```

## Testing

Run the test script:

```bash
python3 test_advanced_features.py
```

This will test:
- RAG indexing and search
- Plan creation and execution
- Agent delegation
- Tool chaining
- Code sandbox
- Metrics tracking

## Performance Considerations

### RAG Memory
- Initial indexing takes 30-60 seconds for ~50 files
- Search queries: 50-100ms
- Storage: ~10MB per 1000 code files

### Code Sandbox
- With Docker: +500ms overhead per execution
- Without Docker: Faster but less secure
- Memory limit: 512MB per container

### Agent Evaluation
- SQLite database grows ~1KB per execution
- Query performance stays fast up to 100k+ records

## Troubleshooting

### "chromadb not found"
```bash
pip install chromadb sentence-transformers
```

### "Docker daemon not running"
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

### "Permission denied (Docker)"
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### RAG search returns no results
```bash
# Re-index codebase
python3 -c "from tools.rag_tools import RAGMemory; RAGMemory().index_codebase()"
```

## Next Steps

1. Integrate features one at a time
2. Test each feature independently
3. Monitor performance with evaluation system
4. Iterate based on metrics and suggestions
5. Expand tool registry for tool chaining
6. Add more agent capabilities

## Examples in Production

See `examples/` directory for:
- `example_rag_usage.py` - RAG integration examples
- `example_planning.py` - Complex task planning
- `example_collaboration.py` - Multi-agent workflows
- `example_tool_chains.py` - Common tool chain patterns

## Support

If you encounter issues:
1. Check logs in `memory/` directory
2. Run test script for diagnostics
3. Review metrics in evaluation database
4. Check Docker logs: `docker logs <container_id>`
