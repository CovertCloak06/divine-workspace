#!/usr/bin/env python3
"""
Shadow OSINT - Dork Generator
Google, GitHub, and Shodan dork generation
"""

from typing import Dict, Any, List
from urllib.parse import quote


class DorkGenerator:
    """Generate search dorks for various platforms."""

    def __init__(self):
        self.google_operators = [
            "site:", "inurl:", "intitle:", "intext:", "filetype:",
            "ext:", "cache:", "link:", "related:", "info:",
        ]

    def google_dorks(
        self,
        target: str,
        target_type: str = "domain"
    ) -> Dict[str, Any]:
        """
        Generate Google dorks for a target.

        Args:
            target: Domain, company name, or username
            target_type: "domain", "company", "username", "email"
        """
        dorks = {
            "target": target,
            "type": target_type,
            "categories": {},
        }

        if target_type == "domain":
            dorks["categories"] = {
                "exposed_files": [
                    f'site:{target} ext:sql | ext:db | ext:log | ext:cfg | ext:env',
                    f'site:{target} ext:xml | ext:conf | ext:cnf | ext:reg',
                    f'site:{target} ext:txt "password" | "username" | "api_key"',
                    f'site:{target} filetype:pdf | filetype:doc | filetype:xls',
                    f'site:{target} filetype:bak | filetype:old | filetype:backup',
                ],
                "sensitive_directories": [
                    f'site:{target} inurl:admin | inurl:login | inurl:portal',
                    f'site:{target} inurl:wp-admin | inurl:wp-content',
                    f'site:{target} inurl:phpmyadmin | inurl:cpanel',
                    f'site:{target} inurl:config | inurl:setup | inurl:install',
                    f'site:{target} inurl:api | inurl:swagger | inurl:graphql',
                    f'site:{target} intitle:"index of" | intitle:"directory listing"',
                ],
                "error_messages": [
                    f'site:{target} "sql syntax" | "mysql error" | "postgresql"',
                    f'site:{target} "warning:" | "fatal error:" | "exception"',
                    f'site:{target} "stack trace" | "traceback"',
                    f'site:{target} "debug" | "development"',
                ],
                "credentials": [
                    f'site:{target} "password" filetype:log',
                    f'site:{target} "api_key" | "apikey" | "api-key"',
                    f'site:{target} "secret" | "token" | "bearer"',
                    f'site:{target} "@{target}" "password"',
                ],
                "subdomains": [
                    f'site:*.{target}',
                    f'site:*.*.{target}',
                    f'-site:www.{target} site:{target}',
                ],
                "technology": [
                    f'site:{target} "powered by"',
                    f'site:{target} inurl:php | inurl:asp | inurl:jsp',
                    f'site:{target} "server:" | "x-powered-by:"',
                ],
            }

        elif target_type == "company":
            dorks["categories"] = {
                "documents": [
                    f'"{target}" filetype:pdf | filetype:doc | filetype:ppt',
                    f'"{target}" filetype:xls "confidential" | "internal"',
                    f'"{target}" "employee" filetype:pdf',
                    f'"{target}" "salary" | "compensation" filetype:pdf',
                ],
                "employees": [
                    f'site:linkedin.com/in "{target}"',
                    f'site:github.com "{target}"',
                    f'"{target}" "@gmail.com" | "@yahoo.com"',
                ],
                "infrastructure": [
                    f'"{target}" "vpn" | "remote access"',
                    f'"{target}" "intranet" | "portal"',
                    f'"{target}" "confluence" | "jira" | "sharepoint"',
                ],
            }

        elif target_type == "username":
            dorks["categories"] = {
                "profiles": [
                    f'"{target}" site:github.com',
                    f'"{target}" site:linkedin.com',
                    f'"{target}" site:twitter.com',
                    f'inurl:"{target}" site:pastebin.com',
                ],
                "code": [
                    f'"{target}" site:github.com password | secret | api_key',
                    f'"{target}" site:gist.github.com',
                    f'"{target}" site:gitlab.com',
                ],
                "forums": [
                    f'"{target}" site:reddit.com',
                    f'"{target}" site:stackoverflow.com',
                    f'"{target}" site:hackforums.net',
                ],
            }

        elif target_type == "email":
            username = target.split("@")[0]
            domain = target.split("@")[1] if "@" in target else ""

            dorks["categories"] = {
                "direct": [
                    f'"{target}"',
                    f'"{target}" password | credentials',
                    f'"{target}" site:pastebin.com',
                ],
                "breaches": [
                    f'"{target}" "leaked" | "breach" | "dump"',
                    f'"{target}" site:haveibeenpwned.com',
                ],
                "related": [
                    f'"{username}" site:github.com',
                    f'"{username}" site:linkedin.com',
                ],
            }

        # Generate search URLs
        dorks["search_urls"] = {}
        for category, queries in dorks["categories"].items():
            dorks["search_urls"][category] = [
                f"https://www.google.com/search?q={quote(q)}"
                for q in queries
            ]

        return dorks

    def github_dorks(self, target: str, target_type: str = "org") -> Dict[str, Any]:
        """
        Generate GitHub search dorks.

        Args:
            target: Organization, username, or domain
            target_type: "org", "user", "domain"
        """
        dorks = {
            "target": target,
            "type": target_type,
            "queries": {},
        }

        base_queries = {
            "credentials": [
                f'{target} password',
                f'{target} secret',
                f'{target} api_key OR apikey OR api-key',
                f'{target} token',
                f'{target} bearer',
                f'{target} oauth',
                f'{target} aws_access_key_id',
                f'{target} private_key',
            ],
            "config_files": [
                f'{target} filename:.env',
                f'{target} filename:.npmrc',
                f'{target} filename:.dockercfg',
                f'{target} filename:id_rsa',
                f'{target} filename:.htpasswd',
                f'{target} filename:wp-config.php',
                f'{target} filename:configuration.php',
                f'{target} filename:config.php',
            ],
            "sensitive_data": [
                f'{target} filename:.bash_history',
                f'{target} filename:.git-credentials',
                f'{target} filename:shadow',
                f'{target} filename:passwd',
                f'{target} "BEGIN RSA PRIVATE KEY"',
                f'{target} "BEGIN OPENSSH PRIVATE KEY"',
            ],
            "database": [
                f'{target} filename:.sql',
                f'{target} filename:dump.sql',
                f'{target} filename:backup.sql',
                f'{target} "mysql" password',
                f'{target} "mongodb" password',
                f'{target} "postgresql" password',
            ],
        }

        if target_type == "org":
            dorks["queries"] = {
                **base_queries,
                "org_specific": [
                    f'org:{target} password',
                    f'org:{target} secret',
                    f'org:{target} filename:.env',
                ],
            }
        elif target_type == "user":
            dorks["queries"] = {
                **base_queries,
                "user_specific": [
                    f'user:{target} password',
                    f'user:{target} secret',
                    f'user:{target} filename:.env',
                ],
            }
        else:
            dorks["queries"] = base_queries

        # Generate search URLs
        dorks["search_urls"] = {}
        for category, queries in dorks["queries"].items():
            dorks["search_urls"][category] = [
                f"https://github.com/search?q={quote(q)}&type=code"
                for q in queries
            ]

        return dorks

    def shodan_dorks(self, target: str = None) -> Dict[str, Any]:
        """
        Generate Shodan search queries.

        Args:
            target: Optional domain/org to focus search
        """
        dorks = {
            "target": target,
            "queries": {},
        }

        if target:
            dorks["queries"]["target_specific"] = [
                f'hostname:{target}',
                f'ssl.cert.subject.cn:{target}',
                f'org:"{target}"',
                f'http.title:"{target}"',
            ]

        dorks["queries"]["vulnerable_services"] = [
            'vuln:CVE-2021-44228',  # Log4j
            'vuln:CVE-2021-26855',  # ProxyLogon
            'vuln:CVE-2019-0708',   # BlueKeep
            'vuln:CVE-2017-0144',   # EternalBlue
            '"default password"',
            'http.title:"Index of /"',
        ]

        dorks["queries"]["exposed_services"] = [
            'port:9200 elasticsearch',
            'port:27017 mongodb',
            'port:6379 redis',
            'port:11211 memcached',
            'port:5432 postgresql',
            'port:3306 mysql',
            'port:1433 mssql',
        ]

        dorks["queries"]["iot_industrial"] = [
            '"Server: yawcam"',
            '"Server: webcamXP"',
            'http.title:"DVR"',
            'http.title:"NVR"',
            'port:102 siemens',
            'port:502 modbus',
            '"Schneider Electric"',
        ]

        dorks["queries"]["admin_panels"] = [
            'http.title:"Dashboard"',
            'http.title:"Admin"',
            'http.title:"Login"',
            '"phpmyadmin"',
            '"grafana"',
            '"kibana"',
        ]

        # Generate search URLs
        dorks["search_urls"] = {}
        for category, queries in dorks["queries"].items():
            dorks["search_urls"][category] = [
                f"https://www.shodan.io/search?query={quote(q)}"
                for q in queries
            ]

        return dorks

    def custom_dork(
        self,
        base_query: str,
        operators: Dict[str, str] = None,
        platform: str = "google"
    ) -> Dict[str, Any]:
        """
        Build a custom dork with specified operators.

        Args:
            base_query: Base search term
            operators: Dict of operator:value pairs
            platform: "google", "github", "shodan"
        """
        query_parts = [base_query]

        if operators:
            for op, value in operators.items():
                if platform == "google":
                    query_parts.append(f'{op}:{value}')
                elif platform == "github":
                    query_parts.append(f'{op}:{value}')
                elif platform == "shodan":
                    query_parts.append(f'{op}:"{value}"')

        full_query = " ".join(query_parts)

        urls = {
            "google": f"https://www.google.com/search?q={quote(full_query)}",
            "github": f"https://github.com/search?q={quote(full_query)}&type=code",
            "shodan": f"https://www.shodan.io/search?query={quote(full_query)}",
        }

        return {
            "query": full_query,
            "platform": platform,
            "search_url": urls.get(platform, urls["google"]),
        }
