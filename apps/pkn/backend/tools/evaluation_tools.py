#!/usr/bin/env python3
"""
Agent Evaluation and Performance Tracking System
Monitors agent performance, tracks metrics, and provides insights for improvement
"""

import sqlite3
import time
import json
import statistics
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta


@dataclass
class ExecutionRecord:
    """Record of a single agent execution"""
    id: int
    agent_type: str
    task: str
    task_category: str
    response: str
    duration_ms: int
    success: bool
    error: Optional[str]
    tools_used: List[str]
    user_feedback_rating: Optional[int]  # 1-5 stars
    user_feedback_text: Optional[str]
    session_id: str
    timestamp: float

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['tools_used'] = json.dumps(self.tools_used)
        return d


class AgentEvaluator:
    """
    Tracks and evaluates agent performance over time.
    Provides insights for improvement and identifies weak areas.
    """

    def __init__(self, project_root: str = "/home/gh0st/pkn"):
        self.project_root = Path(project_root)
        self.db_path = self.project_root / "memory" / "agent_performance.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""

        cursor = self.conn.cursor()

        # Executions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_type TEXT NOT NULL,
                task TEXT NOT NULL,
                task_category TEXT,
                response TEXT,
                duration_ms INTEGER,
                success BOOLEAN,
                error TEXT,
                tools_used TEXT,
                user_feedback_rating INTEGER,
                user_feedback_text TEXT,
                session_id TEXT,
                timestamp REAL
            )
        """)

        # Performance metrics cache
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics_cache (
                agent_type TEXT PRIMARY KEY,
                total_executions INTEGER,
                successful_executions INTEGER,
                average_duration_ms REAL,
                success_rate REAL,
                average_rating REAL,
                last_updated REAL
            )
        """)

        # Task categories for classification
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS task_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                keywords TEXT,
                description TEXT
            )
        """)

        # Improvement suggestions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS improvement_suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_type TEXT,
                issue_description TEXT,
                suggested_solution TEXT,
                priority TEXT,
                status TEXT,
                created_at REAL
            )
        """)

        self.conn.commit()

        # Add default task categories if not exists
        self._add_default_categories()

    def _add_default_categories(self):
        """Add default task categories"""

        categories = [
            ('code_writing', 'write,create,implement,build,code,function,class', 'Writing new code'),
            ('code_debugging', 'debug,fix,error,bug,issue,problem', 'Debugging existing code'),
            ('code_review', 'review,check,analyze,examine,audit', 'Reviewing code quality'),
            ('explanation', 'explain,describe,how,what,why', 'Explaining concepts'),
            ('research', 'research,find,search,lookup,documentation', 'Finding information'),
            ('planning', 'plan,design,architect,structure', 'Planning and design'),
            ('testing', 'test,verify,validate,check', 'Testing code'),
            ('refactoring', 'refactor,improve,optimize,clean', 'Refactoring code'),
            ('question', 'question,ask,help,confused', 'General questions'),
            ('other', '', 'Miscellaneous tasks')
        ]

        cursor = self.conn.cursor()
        for name, keywords, description in categories:
            cursor.execute("""
                INSERT OR IGNORE INTO task_categories (name, keywords, description)
                VALUES (?, ?, ?)
            """, (name, keywords, description))

        self.conn.commit()

    def log_execution(self, agent_type: str, task: str, response: str,
                      duration_ms: int, success: bool, error: Optional[str] = None,
                      tools_used: List[str] = None, session_id: str = "",
                      user_feedback_rating: Optional[int] = None,
                      user_feedback_text: Optional[str] = None):
        """Log an agent execution"""

        # Classify task
        task_category = self._classify_task(task)

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO executions
            (agent_type, task, task_category, response, duration_ms, success, error,
             tools_used, user_feedback_rating, user_feedback_text, session_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            agent_type, task, task_category, response, duration_ms, success, error,
            json.dumps(tools_used or []), user_feedback_rating, user_feedback_text,
            session_id, time.time()
        ))

        self.conn.commit()

        # Update metrics cache
        self._update_metrics_cache(agent_type)

    def _classify_task(self, task: str) -> str:
        """Classify task into a category"""

        task_lower = task.lower()

        cursor = self.conn.cursor()
        cursor.execute("SELECT name, keywords FROM task_categories WHERE keywords != ''")

        best_match = 'other'
        best_score = 0

        for row in cursor.fetchall():
            category = row['name']
            keywords = row['keywords'].split(',')

            score = sum(1 for keyword in keywords if keyword in task_lower)

            if score > best_score:
                best_score = score
                best_match = category

        return best_match

    def _update_metrics_cache(self, agent_type: str):
        """Update cached metrics for an agent"""

        cursor = self.conn.cursor()

        # Calculate metrics
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                AVG(duration_ms) as avg_duration,
                AVG(CASE WHEN user_feedback_rating IS NOT NULL THEN user_feedback_rating ELSE NULL END) as avg_rating
            FROM executions
            WHERE agent_type = ?
        """, (agent_type,))

        row = cursor.fetchone()
        total = row['total']
        successful = row['successful']
        avg_duration = row['avg_duration'] or 0
        avg_rating = row['avg_rating'] or 0
        success_rate = (successful / total * 100) if total > 0 else 0

        # Update cache
        cursor.execute("""
            INSERT OR REPLACE INTO metrics_cache
            (agent_type, total_executions, successful_executions, average_duration_ms,
             success_rate, average_rating, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (agent_type, total, successful, avg_duration, success_rate, avg_rating, time.time()))

        self.conn.commit()

    def get_agent_metrics(self, agent_type: str, days: int = 30) -> Dict[str, Any]:
        """Get performance metrics for an agent"""

        cursor = self.conn.cursor()

        # Time window
        since = time.time() - (days * 86400)

        # Overall metrics
        cursor.execute("""
            SELECT
                COUNT(*) as total_executions,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                AVG(duration_ms) as avg_duration,
                MIN(duration_ms) as min_duration,
                MAX(duration_ms) as max_duration,
                AVG(CASE WHEN user_feedback_rating IS NOT NULL THEN user_feedback_rating ELSE NULL END) as avg_rating
            FROM executions
            WHERE agent_type = ? AND timestamp >= ?
        """, (agent_type, since))

        row = cursor.fetchone()
        total = row['total_executions']

        metrics = {
            'agent_type': agent_type,
            'time_window_days': days,
            'total_executions': total,
            'successful_executions': row['successful'],
            'failed_executions': total - row['successful'],
            'success_rate': (row['successful'] / total * 100) if total > 0 else 0,
            'avg_duration_ms': row['avg_duration'] or 0,
            'min_duration_ms': row['min_duration'] or 0,
            'max_duration_ms': row['max_duration'] or 0,
            'avg_user_rating': row['avg_rating'] or 0
        }

        # Performance by task category
        cursor.execute("""
            SELECT
                task_category,
                COUNT(*) as count,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                AVG(duration_ms) as avg_duration
            FROM executions
            WHERE agent_type = ? AND timestamp >= ?
            GROUP BY task_category
            ORDER BY count DESC
        """, (agent_type, since))

        metrics['by_category'] = []
        for row in cursor.fetchall():
            count = row['count']
            metrics['by_category'].append({
                'category': row['task_category'],
                'count': count,
                'success_rate': (row['successful'] / count * 100) if count > 0 else 0,
                'avg_duration_ms': row['avg_duration']
            })

        # Recent errors
        cursor.execute("""
            SELECT task, error, timestamp
            FROM executions
            WHERE agent_type = ? AND success = 0 AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 10
        """, (agent_type, since))

        metrics['recent_errors'] = []
        for row in cursor.fetchall():
            metrics['recent_errors'].append({
                'task': row['task'][:100],
                'error': row['error'],
                'timestamp': row['timestamp']
            })

        return metrics

    def get_weak_areas(self, agent_type: str, min_failures: int = 3) -> List[Dict[str, Any]]:
        """Identify areas where agent struggles"""

        cursor = self.conn.cursor()

        # Find task categories with high failure rate
        cursor.execute("""
            SELECT
                task_category,
                COUNT(*) as total,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failures,
                AVG(CASE WHEN user_feedback_rating IS NOT NULL THEN user_feedback_rating ELSE NULL END) as avg_rating
            FROM executions
            WHERE agent_type = ?
            GROUP BY task_category
            HAVING failures >= ?
            ORDER BY failures DESC
        """, (agent_type, min_failures))

        weak_areas = []
        for row in cursor.fetchall():
            total = row['total']
            failures = row['failures']
            failure_rate = (failures / total * 100) if total > 0 else 0

            # Get example failures
            cursor.execute("""
                SELECT task, error
                FROM executions
                WHERE agent_type = ? AND task_category = ? AND success = 0
                LIMIT 3
            """, (agent_type, row['task_category']))

            examples = [{'task': r['task'][:100], 'error': r['error']} for r in cursor.fetchall()]

            weak_areas.append({
                'category': row['task_category'],
                'total_attempts': total,
                'failures': failures,
                'failure_rate': failure_rate,
                'avg_rating': row['avg_rating'] or 0,
                'example_failures': examples
            })

        return weak_areas

    def compare_agents(self, metric: str = 'success_rate', days: int = 30) -> List[Dict[str, Any]]:
        """Compare all agents on a specific metric"""

        cursor = self.conn.cursor()

        since = time.time() - (days * 86400)

        cursor.execute("""
            SELECT
                agent_type,
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                AVG(duration_ms) as avg_duration,
                AVG(CASE WHEN user_feedback_rating IS NOT NULL THEN user_feedback_rating ELSE NULL END) as avg_rating
            FROM executions
            WHERE timestamp >= ?
            GROUP BY agent_type
            ORDER BY agent_type
        """, (since,))

        comparisons = []
        for row in cursor.fetchall():
            total = row['total']
            comparisons.append({
                'agent_type': row['agent_type'],
                'total_executions': total,
                'success_rate': (row['successful'] / total * 100) if total > 0 else 0,
                'avg_duration_ms': row['avg_duration'] or 0,
                'avg_user_rating': row['avg_rating'] or 0
            })

        # Sort by requested metric
        if metric == 'success_rate':
            comparisons.sort(key=lambda x: x['success_rate'], reverse=True)
        elif metric == 'speed':
            comparisons.sort(key=lambda x: x['avg_duration_ms'])
        elif metric == 'rating':
            comparisons.sort(key=lambda x: x['avg_user_rating'], reverse=True)

        return comparisons

    def generate_improvement_suggestions(self, agent_type: str) -> List[Dict[str, Any]]:
        """Generate suggestions for improving an agent"""

        suggestions = []

        # Check weak areas
        weak_areas = self.get_weak_areas(agent_type)

        for area in weak_areas:
            if area['failure_rate'] > 50:
                suggestion = {
                    'priority': 'high',
                    'issue': f"High failure rate ({area['failure_rate']:.1f}%) in {area['category']} tasks",
                    'suggestions': [
                        f"Review and improve system prompt for {area['category']} tasks",
                        f"Add specialized tools for {area['category']} operations",
                        f"Collect more training examples for {area['category']} scenarios"
                    ],
                    'examples': area['example_failures']
                }
                suggestions.append(suggestion)

        # Check performance issues
        metrics = self.get_agent_metrics(agent_type)

        if metrics['avg_duration_ms'] > 10000:  # More than 10 seconds
            suggestions.append({
                'priority': 'medium',
                'issue': f"Slow average response time ({metrics['avg_duration_ms']/1000:.1f}s)",
                'suggestions': [
                    "Consider using a faster model for this agent",
                    "Optimize prompts to be more concise",
                    "Enable caching for frequently used contexts",
                    "Increase n_batch or n_gpu_layers in llama.cpp settings"
                ]
            })

        if metrics['avg_user_rating'] < 3.5 and metrics['avg_user_rating'] > 0:
            suggestions.append({
                'priority': 'high',
                'issue': f"Low user satisfaction rating ({metrics['avg_user_rating']:.1f}/5)",
                'suggestions': [
                    "Analyze low-rated responses for common issues",
                    "Improve response formatting and structure",
                    "Add more context-awareness to responses",
                    "Consider A/B testing different system prompts"
                ]
            })

        return suggestions

    def export_metrics(self, output_file: Optional[str] = None) -> str:
        """Export all metrics to JSON file"""

        export_data = {
            'export_timestamp': time.time(),
            'export_date': datetime.now().isoformat(),
            'agents': {}
        }

        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT agent_type FROM executions")

        for row in cursor.fetchall():
            agent_type = row['agent_type']
            export_data['agents'][agent_type] = {
                'metrics': self.get_agent_metrics(agent_type, days=30),
                'weak_areas': self.get_weak_areas(agent_type),
                'improvements': self.generate_improvement_suggestions(agent_type)
            }

        export_data['agent_comparison'] = self.compare_agents('success_rate', days=30)

        # Save to file
        if not output_file:
            output_file = self.project_root / "memory" / f"metrics_export_{int(time.time())}.json"

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        return str(output_file)

    def get_summary_report(self, days: int = 7) -> str:
        """Generate a human-readable summary report"""

        since = time.time() - (days * 86400)

        cursor = self.conn.cursor()

        # Overall stats
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                COUNT(DISTINCT agent_type) as agent_count,
                COUNT(DISTINCT session_id) as session_count
            FROM executions
            WHERE timestamp >= ?
        """, (since,))

        row = cursor.fetchone()
        total = row['total']

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║         Agent Performance Report - Last {days} Days              ║
╚══════════════════════════════════════════════════════════════╝

Overall Statistics:
  • Total Executions: {total}
  • Successful: {row['successful']} ({row['successful']/total*100:.1f}%)
  • Failed: {total - row['successful']} ({(total - row['successful'])/total*100:.1f}%)
  • Active Agents: {row['agent_count']}
  • Sessions: {row['session_count']}

Agent Performance:
"""

        # Per-agent stats
        comparisons = self.compare_agents('success_rate', days)

        for agent_data in comparisons:
            agent = agent_data['agent_type']
            report += f"\n  {agent.upper()}:\n"
            report += f"    Executions: {agent_data['total_executions']}\n"
            report += f"    Success Rate: {agent_data['success_rate']:.1f}%\n"
            report += f"    Avg Duration: {agent_data['avg_duration_ms']/1000:.2f}s\n"
            report += f"    Avg Rating: {agent_data['avg_user_rating']:.1f}/5\n"

        # Top issues
        report += "\n\nAreas Needing Improvement:\n"

        for agent_data in comparisons:
            suggestions = self.generate_improvement_suggestions(agent_data['agent_type'])
            high_priority = [s for s in suggestions if s['priority'] == 'high']

            if high_priority:
                report += f"\n  {agent_data['agent_type'].upper()}:\n"
                for suggestion in high_priority[:2]:
                    report += f"    • {suggestion['issue']}\n"

        return report

    def close(self):
        """Close database connection"""
        self.conn.close()


if __name__ == "__main__":
    print("Agent Evaluation System loaded successfully!")

    evaluator = AgentEvaluator()

    # Show summary
    print(evaluator.get_summary_report(days=7))

    evaluator.close()
