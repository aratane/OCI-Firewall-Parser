# MITRE Technique Definitions
MITRE_ATTACK_TYPES = {
    # Existing entries
    "T1003": "Credential Dumping",
    "T1021": "Remote Services",
    "T1040": "SQL Injection",
    "T1055": "Cross Site Scripting (XSS)",
    "T1059": "Command and Scripting Interpreter",
    "T1083": "Sensitive File Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Directory Traversal",
    "T1210": "Exploitation of Remote Services",
    "T1547": "Boot or Logon Autostart Execution",
    "T1552.001": "Unsecured Credentials: Credentials in Files",
    "T1552.002": "Unsecured Credentials: Credentials in Registry",
    "T1566": "Phishing",
    "T1595": "Active Scanning",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1590": "Gather Victim Network Information",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1583.006": "Acquire Infrastructure: Web Services",
    "T1584.005": "Compromise Infrastructure: Botnet",
    "T1586.002": "Compromise Accounts: Email Accounts",
    "T1608.001": "Stage Capabilities: Upload Malware",
    "T1608.002": "Stage Capabilities: Tool",
    "T1608.003": "Stage Capabilities: Payloads",
    "T1587.001": "Develop Capabilities: Malware",
    "T1587.002": "Develop Capabilities: Tool",
    "T1587.003": "Develop Capabilities: Exploit",
    
    # New entries
    "T1003.001": "Credential Dumping: LSASS Memory",
    "T1003.002": "Credential Dumping: Security Account Manager",
    "T1003.003": "Credential Dumping: /etc/passwd and /etc/shadow",
    "T1003.004": "Credential Dumping: Credential Store",
    "T1003.005": "Credential Dumping: Cached Credentials",
    "T1021.001": "Remote Services: Remote Desktop Web Access",
    "T1021.002": "Remote Services: SSH",
    "T1021.003": "Remote Services: Telnet",
    "T1021.004": "Remote Services: SMB/Windows Admin Shares",
    "T1021.005": "Remote Services: Windows Remote Management",
    "T1040.001": "SQL Injection: Basic SQLi",
    "T1040.002": "SQL Injection: Time-Based Blind",
    "T1040.003": "SQL Injection: Command Execution",
    "T1040.004": "SQL Injection: File Operations",
    "T1040.005": "SQL Injection: Schema Enumeration",
    "T1055.001": "XSS: Basic XSS",
    "T1055.002": "XSS: Event Handler",
    "T1055.003": "XSS: JavaScript Execution",
    "T1055.004": "XSS: DOM-Based",
    "T1055.005": "XSS: HTML Injection",
    "T1059.001": "Command Injection: Command Chain",
    "T1059.002": "Command Injection: Command Substitution",
    "T1059.003": "Command Injection: Path Traversal",
    "T1059.004": "Command Injection: Remote File Download",
    "T1059.005": "Command Injection: PowerShell",
    "T1083.001": "Sensitive File Discovery: Backup Files",
    "T1083.002": "Sensitive File Discovery: Web Server Configs",
    "T1083.003": "Sensitive File Discovery: Version Control",
    "T1083.004": "Sensitive File Discovery: Temporary Files",
    "T1083.005": "Sensitive File Discovery: Log Files",
    "T1105.001": "Ingress Tool Transfer: File Upload",
    "T1105.002": "Ingress Tool Transfer: File Download",
    "T1105.003": "Ingress Tool Transfer: Web File Manager",
    "T1105.004": "Ingress Tool Transfer: File Inclusion",
    "T1105.005": "Ingress Tool Transfer: File Disclosure",
    "T1133.001": "External Remote Services: OAuth",
    "T1133.002": "External Remote Services: SAML",
    "T1133.003": "External Remote Services: Form-Based Auth",
    "T1133.004": "External Remote Services: Exchange Web Services",
    "T1133.005": "External Remote Services: Spring Boot Actuator",
    "T1190.001": "Exploit Public-Facing Application: Joomla",
    "T1190.002": "Exploit Public-Facing Application: Drupal",
    "T1190.003": "Exploit Public-Facing Application: Magento",
    "T1190.004": "Exploit Public-Facing Application: WordPress REST API",
    "T1190.005": "Exploit Public-Facing Application: GraphQL",
    "T1203.001": "Directory Traversal: Encoded",
    "T1203.002": "Directory Traversal: Kernel Files",
    "T1203.003": "Directory Traversal: Java Application Files",
    "T1203.004": "Directory Traversal: File Inclusion",
    "T1203.005": "Directory Traversal: Alternative Paths",
    "T1210.001": "Exploitation of Remote Services: MySQL",
    "T1210.002": "Exploitation of Remote Services: Oracle",
    "T1210.003": "Exploitation of Remote Services: SQL Server",
    "T1210.004": "Exploitation of Remote Services: PostgreSQL",
    "T1210.005": "Exploitation of Remote Services: MongoDB",
    "T1547.001": "Boot or Logon Autostart Execution: Linux Startup Scripts",
    "T1547.002": "Boot or Logon Autostart Execution: Windows Startup Folder",
    "T1547.003": "Boot or Logon Autostart Execution: macOS Launchd",
    "T1547.004": "Boot or Logon Autostart Execution: Cron Jobs",
    "T1547.005": "Boot or Logon Autostart Execution: Library Preload",
    "T1566.004": "Phishing: Password Reset",
    "T1566.005": "Phishing: Financial",
    "T1590.001": "Gather Victim Network Information: Source Code Metadata",
    "T1590.002": "Gather Victim Network Information: SharePoint",
    "T1590.003": "Gather Victim Network Information: Debug Information",
    "T1590.004": "Gather Victim Network Information: IDE Configuration",
    "T1590.005": "Gather Victim Network Information: API Documentation"
}

# MITRE Vulnerability Patterns and Names
MITRE_VULNERABILITY_PATTERNS = {
    # Existing patterns (maintained)
    "T1552.001": {
        "pattern": r"/\.env",
        "vulnerability_name": "Exposed Environment Configuration File"
    },
    "T1552.002": {
        "pattern": r"/\.git",
        "vulnerability_name": "Exposed Git Repository"
    },
    "T1083": {
        "pattern": r"/\.aws|\.backup|\.db|\.credentials|\.config|\.docker|\.dump|\.s3|\.ssh",
        "vulnerability_name": "Sensitive File Exposure"
    },
    "T1595": {
        "pattern": r"/\.well-known/",
        "vulnerability_name": "Well-Known Directory Access"
    },
    "T1190": {
        "pattern": r"/wp-admin|/wp-content|/wp-login\.php|/xmlrpc\.php",
        "vulnerability_name": "WordPress Exploitation Attempt"
    },
    "T1040": {
        "pattern": r"(sql|select|union|from|where)=.*",
        "vulnerability_name": "SQL Injection Attempt"
    },
    "T1203": {
        "pattern": r"\.\./|\.\.\\",
        "vulnerability_name": "Directory Traversal Attempt"
    },
    "T1055": {
        "pattern": r"<script>|javascript:|onerror=",
        "vulnerability_name": "XSS Attempt"
    },
    "T1566": {
        "pattern": r"/mail|email|login|webmail",
        "vulnerability_name": "Phishing Page Access"
    },
    "T1059": {
        "pattern": r"/eval-stdin\.php|/hello\.world|\?lang=|/invokefunction",
        "vulnerability_name": "Command Injection Attempt"
    },
    "T1210": {
        "pattern": r"/phpmyadmin|/pmd|/admin/config\.php|/config\.php",
        "vulnerability_name": "Admin Interface Access"
    },
    "T1590": {
        "pattern": r"/favicon\.ico|/robots\.txt|/sitemap\.xml",
        "vulnerability_name": "Reconnaissance Activity"
    },
    "T1105": {
        "pattern": r"/remote/login|/cgi-bin/authlogin\.cgi|/global-protect/login\.esp|/sslmgr",
        "vulnerability_name": "Remote Login Attempt"
    },
    "T1133": {
        "pattern": r"/logincheck|/remote/fgt_lang",
        "vulnerability_name": "External Authentication Attempt"
    },
    
    # New patterns added below
    "T1003": {
        "pattern": r"/etc/passwd|/etc/shadow|/windows/win\.ini",
        "vulnerability_name": "Credential File Access Attempt"
    },
    "T1021": {
        "pattern": r"/rdp|/remote-desktop|/vnc|:3389|:5900",
        "vulnerability_name": "Remote Desktop Protocol Access"
    },
    "T1547": {
        "pattern": r"/startup|/autostart|/init\.d|/launchd|/launchagents",
        "vulnerability_name": "Autostart Execution Attempt"
    },
    "T1583.001": {
        "pattern": r"/whois|/domain-check|/dns-lookup",
        "vulnerability_name": "Domain Reconnaissance"
    },
    "T1583.006": {
        "pattern": r"/aws-sdk|/azure-api|/google-cloud",
        "vulnerability_name": "Cloud Service Probing"
    },
    "T1584.005": {
        "pattern": r"/botnet|/c2|/command-control",
        "vulnerability_name": "Botnet Communication Attempt"
    },
    "T1586.002": {
        "pattern": r"/email-harvest|/contact-list|/mailing-list",
        "vulnerability_name": "Email Account Enumeration"
    },
    "T1608.001": {
        "pattern": r"/malware-upload|/payload-upload|/file-drop",
        "vulnerability_name": "Malware Upload Endpoint"
    },
    "T1608.002": {
        "pattern": r"/hacking-tools|/exploit-kit|/pentest-tools",
        "vulnerability_name": "Hacking Tools Access"
    },
    "T1608.003": {
        "pattern": r"/payload|/exploit|/shellcode",
        "vulnerability_name": "Exploit Payload Delivery"
    },
    "T1587.001": {
        "pattern": r"/malware-source|/virus-code|/trojan-source",
        "vulnerability_name": "Malware Development Artifacts"
    },
    "T1587.002": {
        "pattern": r"/custom-exploit|/zero-day|/weaponized",
        "vulnerability_name": "Exploit Development Artifacts"
    },
    "T1587.003": {
        "pattern": r"/vulnerability-research|/bug-bounty|/exploit-db",
        "vulnerability_name": "Vulnerability Research Activity"
    },
    "T1566.001": {
        "pattern": r"\.exe$|\.msi$|\.bat$|\.cmd$|\.ps1$",
        "vulnerability_name": "Suspicious File Attachment"
    },
    "T1566.002": {
        "pattern": r"bit\.ly|goo\.gl|tinyurl|urlshortener",
        "vulnerability_name": "URL Shortener Usage"
    },
    "T1566.003": {
        "pattern": r"/linkedin-connect|/facebook-connect|/social-login",
        "vulnerability_name": "Social Media Phishing Attempt"
    },
    "T1003.001": {
        "pattern": r"/lsass\.dmp|/memory\.dmp|/crash-dump",
        "vulnerability_name": "Memory Dump Access"
    },
    "T1003.002": {
        "pattern": r"/SAM|/SYSTEM|/SECURITY|/ntds\.dit",
        "vulnerability_name": "Windows Registry Hive Access"
    },
    "T1003.003": {
        "pattern": r"/etc/shadow|/etc/master\.passwd|/etc/security/passwd",
        "vulnerability_name": "Linux Password File Access"
    },
    "T1003.004": {
        "pattern": r"/keychain|/keyring|/credential-store",
        "vulnerability_name": "Credential Store Access"
    },
    "T1003.005": {
        "pattern": r"/cached-creds|/credential-cache|/ticket",
        "vulnerability_name": "Cached Credential Access"
    },
    "T1021.001": {
        "pattern": r"/tsweb|/remoteapps|/remote-desktop-web",
        "vulnerability_name": "Web-based Remote Desktop Access"
    },
    "T1021.002": {
        "pattern": r"/ssh|/sftp|/scp|:22",
        "vulnerability_name": "SSH Service Access"
    },
    "T1021.003": {
        "pattern": r"/telnet|:23|/rlogin|:513",
        "vulnerability_name": "Telnet Service Access"
    },
    "T1021.004": {
        "pattern": r"/smb|/cifs|:445|:139",
        "vulnerability_name": "SMB Service Access"
    },
    "T1021.005": {
        "pattern": r"/winrm|:5985|:5986",
        "vulnerability_name": "Windows Remote Management Access"
    },
    "T1040.001": {
        "pattern": r"union.*select|select.*from.*where",
        "vulnerability_name": "Basic SQL Injection Pattern"
    },
    "T1040.002": {
        "pattern": r"sleep\(\d+\)|benchmark\(\d+\)|waitfor delay",
        "vulnerability_name": "Time-Based SQL Injection"
    },
    "T1040.003": {
        "pattern": r"exec\(|sp_executesql|xp_cmdshell",
        "vulnerability_name": "Command Execution via SQLi"
    },
    "T1040.004": {
        "pattern": r"load_file\(|into outfile|into dumpfile",
        "vulnerability_name": "File Operations via SQLi"
    },
    "T1040.005": {
        "pattern": r"information_schema|pg_catalog|sys\.tables",
        "vulnerability_name": "Database Schema Enumeration"
    },
    "T1055.001": {
        "pattern": r"alert\(|prompt\(|confirm\(",
        "vulnerability_name": "Basic XSS Payload"
    },
    "T1055.002": {
        "pattern": r"onload=|onmouseover=|onerror=",
        "vulnerability_name": "Event Handler XSS"
    },
    "T1055.003": {
        "pattern": r"eval\(|setTimeout\(|Function\(",
        "vulnerability_name": "JavaScript Execution XSS"
    },
    "T1055.004": {
        "pattern": r"document\.cookie|window\.location|localStorage",
        "vulnerability_name": "DOM-Based XSS"
    },
    "T1055.005": {
        "pattern": r"<iframe|<embed|<object",
        "vulnerability_name": "HTML Injection XSS"
    },
    "T1059.001": {
        "pattern": r";\s*\w+|\|\s*\w+|\&\s*\w+",
        "vulnerability_name": "Command Chain Attempt"
    },
    "T1059.002": {
        "pattern": r"\$\(|`|%\(|%24%28",
        "vulnerability_name": "Command Substitution Attempt"
    },
    "T1059.003": {
        "pattern": r"\.\./\.\./\.\./|/proc/self/|/dev/tcp/",
        "vulnerability_name": "Path Traversal Command"
    },
    "T1059.004": {
        "pattern": r"curl\s|wget\s|ftp\s|nc\s",
        "vulnerability_name": "Remote File Download Attempt"
    },
    "T1059.005": {
        "pattern": r"powershell\s|pwsh\s|iex\s|Invoke-",
        "vulnerability_name": "PowerShell Command Execution"
    },
    "T1083.001": {
        "pattern": r"/backup\.zip|/dump\.sql|/archive\.tar",
        "vulnerability_name": "Backup File Access"
    },
    "T1083.002": {
        "pattern": r"/\.htaccess|/\.htpasswd|/httpd\.conf",
        "vulnerability_name": "Web Server Config Access"
    },
    "T1083.003": {
        "pattern": r"/\.svn|/CVS|/\.bzr|/\.hg",
        "vulnerability_name": "Version Control System Access"
    },
    "T1083.004": {
        "pattern": r"/\.swp|/\.swo|/\.bak|/~$",
        "vulnerability_name": "Temporary File Access"
    },
    "T1083.005": {
        "pattern": r"/logs/|/var/log/|/error_log",
        "vulnerability_name": "Log File Access"
    },
    "T1105.001": {
        "pattern": r"/upload\.php|/fileupload|/import",
        "vulnerability_name": "File Upload Endpoint"
    },
    "T1105.002": {
        "pattern": r"/download\.php|/export|/getfile",
        "vulnerability_name": "File Download Endpoint"
    },
    "T1105.003": {
        "pattern": r"/filemanager|/browser|/elfinder",
        "vulnerability_name": "Web File Manager Access"
    },
    "T1105.004": {
        "pattern": r"/file-include|/local-file-include",
        "vulnerability_name": "File Inclusion Attempt"
    },
    "T1105.005": {
        "pattern": r"/file-read|/file-disclosure",
        "vulnerability_name": "File Disclosure Attempt"
    },
    "T1133.001": {
        "pattern": r"/oauth/authorize|/openid/connect",
        "vulnerability_name": "OAuth Authentication Attempt"
    },
    "T1133.002": {
        "pattern": r"/saml|/adfs|/ws-fed",
        "vulnerability_name": "SAML Authentication Attempt"
    },
    "T1133.003": {
        "pattern": r"/j_spring_security_check|/dologin",
        "vulnerability_name": "Form-Based Authentication Attempt"
    },
    "T1133.004": {
        "pattern": r"/autodiscover|/ews|/mapi",
        "vulnerability_name": "Exchange Web Services Access"
    },
    "T1133.005": {
        "pattern": r"/actuator|/metrics|/heapdump",
        "vulnerability_name": "Spring Boot Actuator Access"
    },
    "T1190.001": {
        "pattern": r"/joomla/administrator|/administrator/index\.php",
        "vulnerability_name": "Joomla Admin Access"
    },
    "T1190.002": {
        "pattern": r"/drupal/admin|/user/login",
        "vulnerability_name": "Drupal Admin Access"
    },
    "T1190.003": {
        "pattern": r"/magento/admin|/admin/dashboard",
        "vulnerability_name": "Magento Admin Access"
    },
    "T1190.004": {
        "pattern": r"/wp-json/wp/v2/users|/wp-json/oembed/",
        "vulnerability_name": "WordPress REST API Access"
    },
    "T1190.005": {
        "pattern": r"/graphql|/api/graphql",
        "vulnerability_name": "GraphQL API Access"
    },
    "T1203.001": {
        "pattern": r"%2e%2e/|%252e%252e/",
        "vulnerability_name": "Encoded Directory Traversal"
    },
    "T1203.002": {
        "pattern": r"/proc/self/|/sys/kernel/",
        "vulnerability_name": "Kernel File Access"
    },
    "T1203.003": {
        "pattern": r"/WEB-INF/|/META-INF/",
        "vulnerability_name": "Java Application File Access"
    },
    "T1203.004": {
        "pattern": r"/include/|/require/|/file=",
        "vulnerability_name": "File Inclusion Attempt"
    },
    "T1203.005": {
        "pattern": r"/\.\\./|/\./\./",
        "vulnerability_name": "Alternative Path Traversal"
    },
    "T1210.001": {
        "pattern": r"/mysql/admin|/mysql/dbadmin",
        "vulnerability_name": "MySQL Admin Access"
    },
    "T1210.002": {
        "pattern": r"/oracle/em|/oracle/console",
        "vulnerability_name": "Oracle Admin Access"
    },
    "T1210.003": {
        "pattern": r"/sqlserver/manager|/sqlserver/webadmin",
        "vulnerability_name": "SQL Server Admin Access"
    },
    "T1210.004": {
        "pattern": r"/postgresql/admin|/pgadmin",
        "vulnerability_name": "PostgreSQL Admin Access"
    },
    "T1210.005": {
        "pattern": r"/mongodb/admin|/mongoclient",
        "vulnerability_name": "MongoDB Admin Access"
    },
    "T1547.001": {
        "pattern": r"/etc/rc\.d|/etc/init\.d|/etc/systemd",
        "vulnerability_name": "Linux Startup Script Access"
    },
    "T1547.002": {
        "pattern": r"/Start Menu/Programs/Startup|/AppData/Roaming/Microsoft/Windows/Start Menu",
        "vulnerability_name": "Windows Startup Folder Access"
    },
    "T1547.003": {
        "pattern": r"/Library/LaunchAgents|/Library/LaunchDaemons",
        "vulnerability_name": "macOS Launchd Access"
    },
    "T1547.004": {
        "pattern": r"/etc/cron\.|/var/spool/cron/",
        "vulnerability_name": "Cron Job Access"
    },
    "T1547.005": {
        "pattern": r"/etc/ld\.so\.preload|/etc/ld\.so\.conf",
        "vulnerability_name": "Library Preload Access"
    },
    "T1566.004": {
        "pattern": r"/password-reset|/forgot-password|/account-recovery",
        "vulnerability_name": "Password Reset Phishing"
    },
    "T1566.005": {
        "pattern": r"/invoice|/payment|/billing",
        "vulnerability_name": "Financial Phishing Attempt"
    },
    "T1590.001": {
        "pattern": r"/.git/HEAD|/package\.json|/composer\.json",
        "vulnerability_name": "Source Code Metadata Access"
    },
    "T1590.002": {
        "pattern": r"/_api|/_vti_bin|/_layouts",
        "vulnerability_name": "SharePoint Reconnaissance"
    },
    "T1590.003": {
        "pattern": r"/_profiler|/_wdt|/_debug",
        "vulnerability_name": "Debug Information Access"
    },
    "T1590.004": {
        "pattern": r"/.idea/|/.vscode/|/project\.xml",
        "vulnerability_name": "IDE Configuration Access"
    },
    "T1590.005": {
        "pattern": r"/api-docs|/swagger|/openapi",
        "vulnerability_name": "API Documentation Access"
    }
}

# MITRE Severity Levels
MITRE_SEVERITY_LEVEL = {
    # Existing entries
    "T1552.001": "CRITICAL",
    "T1552.002": "HIGH",
    "T1083": "MEDIUM",
    "T1595": "LOW",
    "T1190": "CRITICAL",
    "T1040": "HIGH",
    "T1203": "HIGH",
    "T1055": "MEDIUM",
    "T1566": "INFORMATION",
    "T1059": "CRITICAL",
    "T1210": "HIGH",
    "T1590": "LOW",
    "T1105": "MEDIUM",
    "T1133": "HIGH",
    
    # New entries
    "T1003": "CRITICAL",
    "T1021": "HIGH",
    "T1547": "HIGH",
    "T1583.001": "LOW",
    "T1583.006": "MEDIUM",
    "T1584.005": "HIGH",
    "T1586.002": "MEDIUM",
    "T1608.001": "CRITICAL",
    "T1608.002": "HIGH",
    "T1608.003": "HIGH",
    "T1587.001": "HIGH",
    "T1587.002": "HIGH",
    "T1587.003": "MEDIUM",
    "T1566.001": "HIGH",
    "T1566.002": "MEDIUM",
    "T1566.003": "MEDIUM",
    "T1003.001": "CRITICAL",
    "T1003.002": "CRITICAL",
    "T1003.003": "CRITICAL",
    "T1003.004": "HIGH",
    "T1003.005": "HIGH",
    "T1021.001": "HIGH",
    "T1021.002": "HIGH",
    "T1021.003": "HIGH",
    "T1021.004": "HIGH",
    "T1021.005": "HIGH",
    "T1040.001": "HIGH",
    "T1040.002": "HIGH",
    "T1040.003": "CRITICAL",
    "T1040.004": "CRITICAL",
    "T1040.005": "MEDIUM",
    "T1055.001": "MEDIUM",
    "T1055.002": "MEDIUM",
    "T1055.003": "HIGH",
    "T1055.004": "HIGH",
    "T1055.005": "MEDIUM",
    "T1059.001": "HIGH",
    "T1059.002": "HIGH",
    "T1059.003": "CRITICAL",
    "T1059.004": "HIGH",
    "T1059.005": "CRITICAL",
    "T1083.001": "HIGH",
    "T1083.002": "HIGH",
    "T1083.003": "MEDIUM",
    "T1083.004": "MEDIUM",
    "T1083.005": "MEDIUM",
    "T1105.001": "HIGH",
    "T1105.002": "MEDIUM",
    "T1105.003": "HIGH",
    "T1105.004": "CRITICAL",
    "T1105.005": "HIGH",
    "T1133.001": "MEDIUM",
    "T1133.002": "MEDIUM",
    "T1133.003": "MEDIUM",
    "T1133.004": "HIGH",
    "T1133.005": "HIGH",
    "T1190.001": "HIGH",
    "T1190.002": "HIGH",
    "T1190.003": "HIGH",
    "T1190.004": "MEDIUM",
    "T1190.005": "MEDIUM",
    "T1203.001": "HIGH",
    "T1203.002": "CRITICAL",
    "T1203.003": "HIGH",
    "T1203.004": "CRITICAL",
    "T1203.005": "HIGH",
    "T1210.001": "HIGH",
    "T1210.002": "HIGH",
    "T1210.003": "HIGH",
    "T1210.004": "HIGH",
    "T1210.005": "HIGH",
    "T1547.001": "HIGH",
    "T1547.002": "HIGH",
    "T1547.003": "HIGH",
    "T1547.004": "HIGH",
    "T1547.005": "HIGH",
    "T1566.004": "MEDIUM",
    "T1566.005": "MEDIUM",
    "T1590.001": "MEDIUM",
    "T1590.002": "LOW",
    "T1590.003": "MEDIUM",
    "T1590.004": "LOW",
    "T1590.005": "MEDIUM"
}