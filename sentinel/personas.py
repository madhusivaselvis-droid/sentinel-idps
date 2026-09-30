"""
personas.py
Defines a pool of persona profiles and assigns one per connection.
Each persona varies banner text, response timing jitter, and fake content,
so repeated scans don't see an identical fingerprint every time.
"""

import random

PERSONAS = [
    {
        "name": "ubuntu-legacy",
        "ssh_banner": "SSH-2.0-OpenSSH_7.4",
        "http_server_header": "Apache/2.4.29 (Ubuntu)",
        "jitter_ms": (20, 80),
        "fake_files": ["backup.tar.gz", "config.old", "notes.txt"],
        "page_title": "Company Intranet",
    },
    {
        "name": "centos-old",
        "ssh_banner": "SSH-2.0-OpenSSH_6.6.1",
        "http_server_header": "Apache/2.2.15 (CentOS)",
        "jitter_ms": (10, 40),
        "fake_files": ["db_dump.sql", "id_rsa.bak", "todo.md"],
        "page_title": "Internal Services Portal",
    },
    {
        "name": "debian-mid",
        "ssh_banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5",
        "http_server_header": "nginx/1.18.0 (Ubuntu)",
        "jitter_ms": (5, 60),
        "fake_files": ["credentials.yaml", "staging.env", "readme.old"],
        "page_title": "Staging Environment",
    },
    {
        "name": "windows-iis",
        "ssh_banner": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "http_server_header": "Microsoft-IIS/10.0",
        "jitter_ms": (15, 50),
        "fake_files": ["web.config.bak", "users.xlsx", "install_notes.txt"],
        "page_title": "Corporate Web Services",
    },
]

RABBIT_HOLE_PERSONA = {
    "name": "rabbit-hole-deep",
    "ssh_banner": "SSH-2.0-OpenSSH_5.3",
    "http_server_header": "Apache/2.2.3",
    "jitter_ms": (150, 400),   # deliberately slower, richer, heavier logging
    "fake_files": [
        "database_backup_2024.sql", "employee_records.csv",
        "vpn_configs/", "internal_wiki_export.zip", "passwords_DO_NOT_SHARE.txt"
    ],
    "page_title": "Legacy Admin Console",
}


def assign_persona() -> dict:
    """Pick a persona at random for a new connection."""
    return random.choice(PERSONAS)


def get_rabbit_hole() -> dict:
    """Return the deep, heavily-instrumented redirect persona."""
    return RABBIT_HOLE_PERSONA
