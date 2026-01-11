"""
Task Classification Module
Analyzes tasks and routes to appropriate agents
"""

from typing import Dict, Any
from .types import AgentType, TaskComplexity


class TaskClassifier:
    """Classifies tasks and determines appropriate agent routing"""

    def __init__(self):
        pass

    def classify(self, instruction: str) -> Dict[str, Any]:
        """
        Classify task by type, complexity, and required agent.

        Returns:
            {
                'agent_type': AgentType,
                'complexity': TaskComplexity,
                'confidence': float,
                'reasoning': str,
                'requires_tools': bool
            }
        """
        instruction_lower = instruction.lower()

        # Code-related keywords
        code_keywords = [
            'code', 'function', 'class', 'debug', 'bug', 'error', 'refactor',
            'implement', 'write code', 'python', 'javascript', 'script',
            'algorithm', 'optimize', 'fix', 'syntax', 'variable'
        ]

        # Research keywords
        research_keywords = [
            'search', 'find', 'lookup', 'research', 'what is', 'who is',
            'when did', 'how to', 'wikipedia', 'documentation', 'docs',
            'latest', 'current', 'news', 'github', 'library'
        ]

        # Execution keywords
        execute_keywords = [
            'run', 'execute', 'list files', 'read file', 'write file',
            'create file', 'delete', 'move', 'copy', 'command', 'bash',
            'shell', 'directory'
        ]

        # Planning/reasoning keywords
        planning_keywords = [
            'plan', 'strategy', 'approach', 'analyze', 'compare', 'evaluate',
            'pros and cons', 'should i', 'which', 'best way', 'explain why',
            'logic', 'reasoning'
        ]

        # Consultant keywords (complex decisions, voting, expert advice)
        consultant_keywords = [
            'vote', 'decide', 'choose between', 'which option', 'expert opinion',
            'deep thought', 'complex decision', 'consult', 'advise', 'recommend',
            'philosophical', 'ethical', 'strategic decision', 'critical choice'
        ]

        # Security/Cybersecurity keywords (UNCENSORED - pentesting, hacking, security)
        security_keywords = [
            'hack', 'hacking', 'exploit', 'vulnerability', 'vuln', 'penetration test',
            'pentest', 'security', 'cybersecurity', 'injection', 'xss', 'csrf',
            'sql injection', 'buffer overflow', 'reverse engineering', 'malware',
            'backdoor', 'rootkit', 'privilege escalation', 'brute force', 'crack',
            'password crack', 'hash', 'decrypt', 'encryption', 'cryptography',
            'nmap', 'metasploit', 'burp suite', 'wireshark', 'kali', 'red team',
            'blue team', 'threat', 'attack', 'payload', 'shellcode', 'zero day',
            'cve', 'security audit', 'web security', 'network security', 'firewall',
            'bypass', 'evade', 'stealth', 'osint', 'reconnaissance', 'footprint',
            'enumeration', 'port scan', 'directory traversal', 'lfi', 'rfi',
            'command injection', 'code injection', 'deserialization', 'xxe'
        ]

        # Vision/Image analysis keywords
        vision_keywords = [
            'image', 'screenshot', 'picture', 'photo', 'visual', 'see', 'look at',
            'what do you see', 'analyze image', 'describe image', 'ui', 'interface',
            'diagram', 'chart', 'graph', 'drawing', 'render', 'displayed', 'shown',
            'screen', 'display', 'visible', 'ocr', 'read text from', 'extract text',
            'recognize', 'detect', 'identify in image', 'what\'s in', 'show me'
        ]

        # Count keyword matches
        code_score = sum(1 for kw in code_keywords if kw in instruction_lower)
        research_score = sum(1 for kw in research_keywords if kw in instruction_lower)
        execute_score = sum(1 for kw in execute_keywords if kw in instruction_lower)
        planning_score = sum(1 for kw in planning_keywords if kw in instruction_lower)
        consultant_score = sum(1 for kw in consultant_keywords if kw in instruction_lower)
        security_score = sum(1 for kw in security_keywords if kw in instruction_lower)
        vision_score = sum(1 for kw in vision_keywords if kw in instruction_lower)

        # Determine agent type and complexity
        scores = {
            AgentType.CODER: code_score,
            AgentType.RESEARCHER: research_score,
            AgentType.EXECUTOR: execute_score,
            AgentType.REASONER: planning_score,
            AgentType.CONSULTANT: consultant_score * 2,  # Weight consultant higher
            AgentType.SECURITY: security_score * 2.5,  # Weight security highest for safety
            AgentType.VISION: vision_score * 2,  # Weight vision high for image tasks (local)
            AgentType.VISION_CLOUD: vision_score * 2,  # Same weight as local vision
            AgentType.GENERAL: 0  # Default agent, always has score 0
        }

        # Get highest scoring agent
        if max(scores.values()) > 0:
            agent_type = max(scores, key=scores.get)
            confidence = min(scores[agent_type] / 3.0, 1.0)  # Normalize to 0-1
        else:
            # Default to general for simple questions
            agent_type = AgentType.GENERAL
            confidence = 0.5

        # Determine complexity
        word_count = len(instruction.split())
        has_multi_steps = any(word in instruction_lower for word in ['and then', 'after that', 'next', 'also', 'additionally'])

        if word_count < 10 and not has_multi_steps:
            complexity = TaskComplexity.SIMPLE
        elif word_count < 30 and not has_multi_steps:
            complexity = TaskComplexity.MEDIUM
        else:
            complexity = TaskComplexity.COMPLEX

        # Determine if tools are needed
        requires_tools = agent_type in [AgentType.RESEARCHER, AgentType.EXECUTOR, AgentType.CODER, AgentType.SECURITY]

        return {
            'agent_type': agent_type,  # Keep as enum for internal use
            'complexity': complexity,  # Keep as enum for internal use
            'confidence': confidence,
            'reasoning': f"Matched {agent_type.value} keywords (score: {scores[agent_type]})",
            'requires_tools': requires_tools,
            'word_count': word_count,
            'has_multi_steps': has_multi_steps
        }


    def route(self, instruction: str, conversation_id: str = None) -> Dict[str, Any]:
        """
        Route a task to the most appropriate agent.

        Args:
            instruction: The task to perform
            conversation_id: Optional conversation ID for context

        Returns:
            {
                'agent': AgentType,
                'classification': dict,
                'strategy': 'single_agent' | 'multi_agent',
                'estimated_time': str
            }
        """
        classification = self.classify_task(instruction)

        # Determine strategy
        if classification['complexity'] == TaskComplexity.COMPLEX:
            strategy = 'multi_agent'
        else:
            strategy = 'single_agent'

        # Estimate time based on agent and complexity
        agent_config = self.agents[classification['agent_type']]
        speed = agent_config['speed']

        time_estimates = {
            'fast': '2-5 seconds',
            'medium': '5-15 seconds',
            'slow': '10-30 seconds',
            'very_slow': '30-120 seconds'
        }

        return {
            'agent': classification['agent_type'],  # Keep as enum for internal use
            'classification': classification,
            'strategy': strategy,
            'estimated_time': time_estimates.get(speed, 'unknown'),
            'agent_config': agent_config
        }

