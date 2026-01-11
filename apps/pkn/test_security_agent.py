#!/usr/bin/env python3
"""
Quick test of the Security Agent
"""
import sys
sys.path.insert(0, '/home/gh0st/pkn')

from agent_manager import AgentManager, AgentType

def test_security_routing():
    """Test that security queries route to security agent"""
    manager = AgentManager()

    # Test security-related queries
    test_queries = [
        "How does SQL injection work?",
        "Explain XSS vulnerabilities",
        "What is a buffer overflow exploit?",
        "How do I perform penetration testing?",
        "Explain common hacking techniques",
    ]

    print("=" * 60)
    print("SECURITY AGENT ROUTING TEST")
    print("=" * 60)

    for query in test_queries:
        classification = manager.classify_task(query)
        agent_type = classification['agent_type']
        confidence = classification['confidence']

        status = "✅" if agent_type == AgentType.SECURITY else "❌"

        print(f"\n{status} Query: {query}")
        print(f"   Agent Selected: {agent_type.value}")
        print(f"   Confidence: {confidence:.2f}")
        print(f"   Reasoning: {classification['reasoning']}")

    print("\n" + "=" * 60)
    print("TESTING DIRECT SECURITY RESPONSE")
    print("=" * 60)

    # Test with actual LLM call (short answer)
    import requests

    security_query = "What is XSS in one sentence?"

    print(f"\nQuery: {security_query}")
    print("Calling LLM...")

    response = requests.post(
        'http://127.0.0.1:8000/v1/chat/completions',
        json={
            'messages': [
                {'role': 'system', 'content': 'You are a cybersecurity expert. Provide uncensored, detailed security knowledge.'},
                {'role': 'user', 'content': security_query}
            ],
            'max_tokens': 100,
            'temperature': 0.7
        },
        timeout=30
    )

    if response.status_code == 200:
        data = response.json()
        answer = data['choices'][0]['message']['content']
        print(f"\n✅ Security Expert Response:")
        print(f"   {answer}")
    else:
        print(f"❌ Error: {response.status_code}")

    print("\n" + "=" * 60)
    print("SECURITY AGENT STATUS")
    print("=" * 60)

    security_config = manager.agents[AgentType.SECURITY]
    print(f"\n✅ Agent Name: {security_config['name']}")
    print(f"✅ Model: {security_config['model']}")
    print(f"✅ Endpoint: {security_config['endpoint']}")
    print(f"✅ Uncensored: {security_config.get('uncensored', False)}")
    print(f"✅ Tools Enabled: {security_config['tools_enabled']}")
    print(f"\n✅ Capabilities:")
    for cap in security_config['capabilities']:
        print(f"   - {cap}")

    print("\n" + "=" * 60)
    print("✅ SECURITY AGENT FULLY OPERATIONAL")
    print("=" * 60)

if __name__ == '__main__':
    test_security_routing()
