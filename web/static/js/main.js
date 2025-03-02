// Main JavaScript for CyberAI web interface

document.addEventListener('DOMContentLoaded', () => {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
    });

    // Confirm dialogs for important actions
    document.querySelectorAll('.confirm-action').forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm-message') || 'Are you sure you want to perform this action?')) {
                e.preventDefault();
            }
        });
    });

    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.alert:not(.alert-permanent)');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.classList.add('fade');
            setTimeout(() => {
                message.remove();
            }, 500);
        }, 5000);
    });

    // Log analyzer source selection
    const sourceSelect = document.getElementById('log-source');
    const logTextarea = document.getElementById('log-content');
    const sourceHints = {
        'fortinet': 'Example: date=2023-09-10 time=08:30:45 devname="FGT60F" devid="FG100ABCDEF" logid="0001000014" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.5 srcport=45678 srcintf="port1" srcintfrole="lan" dstip=8.8.8.8 dstport=53 dstintf="wan1" dstintfrole="wan" sessionid=123456 proto=17 action="deny" policyid=1 policytype="policy" service="DNS" dstcountry="United States" srccountry="Reserved" trandisp="noop" duration=60 sentbyte=1030 rcvdbyte=1326 sentpkt=5 rcvdpkt=5 appcat="unscanned" crscore=30 craction=131072 crlevel="high"',
        'linux-syslog': 'Example: Sep 10 09:32:45 myserver sshd[12345]: Failed password for invalid user admin from 203.0.113.100 port 39654 ssh2',
        'azure-waf': 'Example: {"time":"2023-09-10T10:15:30Z","resourceId":"/SUBSCRIPTIONS/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/RESOURCEGROUPS/MYRESOURCEGROUP/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/MYAPPGATEWAY","operationName":"ApplicationGatewayFirewall","category":"ApplicationGatewayFirewallLog","properties":{"instanceId":"appgw_1","clientIP":"203.0.113.5","clientPort":"35425","requestUri":"/admin/login.php","ruleSetType":"OWASP","ruleSetVersion":"3.0","ruleId":"942100","message":"SQL Injection Attack Detected via libinjection","action":"Blocked","site":"Global","details":{"message":"Warning. Pattern match \"(?i:(?:[\\\\\\\\\"\\\\']\\\\s*?(?:n?and|x?or|not|sub|\\\\|\\\\/\\\\|)\\\\s*?[\\\\\\\\\\\"\\\\']\\\\s*?\\\\=\\\\s*?[\\\\\\\\\\\"\\\\'])|(?:(?:n?and|x?or|not|sub|\\\\|\\\\/\\\\|)\\\\s+[\\\\d\\\\w]+\\\\s*?[\\\\-+]\\\\s*?[\\\\d\\\\w]+\\\\s*?\\\\=\\\\s*?\\\\d+)|(?:[\\\\\\\\\\\"\\\\']\\\\s*?\\\\w+\\\\s*?[\\\\-+]\\\\s*?[\\\\d\\\\w]+\\\\s*?\\\\=\\\\s*?[\\\\\\\\\\\"\\\\']\\\\d+)|(?:[\\\\\\\\\\\"\\\\']\\\\s*?[\\\\d\\\\w]+\\\\s*?[\\\\-+]\\\\s*?[\\\\d\\\\w]+\\\\s*?\\\\=\\\\s*?[\\\\\\\\\\\"\\\\']\\\\d+)|(?:[\\\\\\\\\\\"\\\\']\\\\s*?[\\\\d\\\\w]+\\\\s*?[\\\\-+]\\\\s*?[\\\\d\\\\w]+\\\\s*?\\\\=\\\\s*?[\\\\d\\\\w]+\\\\s*?[\\\\-+]\\\\s*?[\\\\\\\\\\\"\\\\'])|(?:(?:n?and|x?or|not|sub|\\\\|\\\\/\\\\|)\\\\s+[\\\\\\\\\\\"\\\\'][^\\\\-+\\\\s]+[\\\\\\\\\\\"\\\\']\\\\s*?[\\\\-+]\\\\s*?[\\\\d\\\\w]+\\\\s*?\\\\=\\\\s*?\\\\d+)|(?:(?:n?and|x?or|not|sub|\\\\|\\\\/\\\\|)\\\\s+[\\\\d\\\\w]+\\\\s*?[\\\\-+]\\\\s*?[\\\\\\\\\\\"\\\\'][^\\\\-+\\\\s]+[\\\\\\\\\\\"\\\\']\\\\s*?\\\\=\\\\s*?\\\\d+)\" at ARGS:username. [file \\\"/owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\\\"] [line \"500\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: SQL injection found within ARGS:username: ' OR 1=1--\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.0.0\"] [tag \"application-multi\"] [tag \"language-multi\"] [tag \"platform-multi\"] [tag \"attack-sqli\"] [tag \"OWASP_CRS/WEB_ATTACK/SQL_INJECTION\"] [tag \"WASCTC/WASC-19\"] [tag \"OWASP_TOP_10/A1\"] [tag \"OWASP_AppSensor/CIE1\"] [tag \"PCI/6.5.2\"]","details":{"message":"' OR 1=1--","data":"' OR 1=1--","file":"/owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","line":"500","id":"942100"}}}}',
        'windows-event': 'Example: <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="2023-09-10T12:24:30.123456Z"/><EventRecordID>5478</EventRecordID><Correlation/><Execution ProcessID="500" ThreadID="1024"/><Channel>Security</Channel><Computer>WIN-DC01.contoso.local</Computer><Security/></System><EventData><Data Name="SubjectUserSid">S-1-0-0</Data><Data Name="SubjectUserName">-</Data><Data Name="SubjectDomainName">-</Data><Data Name="SubjectLogonId">0x0</Data><Data Name="TargetUserSid">S-1-0-0</Data><Data Name="TargetUserName">Administrator</Data><Data Name="TargetDomainName">CONTOSO</Data><Data Name="Status">0xC000006D</Data><Data Name="FailureReason">%%2313</Data><Data Name="SubStatus">0xC0000064</Data><Data Name="LogonType">3</Data><Data Name="LogonProcessName">NtLmSsp</Data><Data Name="AuthenticationPackageName">NTLM</Data><Data Name="WorkstationName">WORKSTATION01</Data><Data Name="TransmittedServices">-</Data><Data Name="LmPackageName">-</Data><Data Name="KeyLength">0</Data><Data Name="ProcessId">0x0</Data><Data Name="ProcessName">-</Data><Data Name="IpAddress">203.0.113.201</Data><Data Name="IpPort">50300</Data></EventData></Event>'
    };
    
    if (sourceSelect && logTextarea) {
        sourceSelect.addEventListener('change', function() {
            const selectedSource = this.value;
            if (sourceHints[selectedSource]) {
                // Only show hint if the textarea is empty
                if (!logTextarea.value.trim()) {
                    logTextarea.placeholder = sourceHints[selectedSource];
                }
            }
        });
        
        // Set initial placeholder based on default selection
        if (sourceSelect.value && sourceHints[sourceSelect.value] && !logTextarea.value.trim()) {
            logTextarea.placeholder = sourceHints[sourceSelect.value];
        }
    }

    // Dark mode toggle functionality
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const htmlElement = document.documentElement;
    
    if (darkModeToggle) {
        // Check for saved theme preference or respect OS preference
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
            enableDarkMode();
        }
        
        darkModeToggle.addEventListener('click', () => {
            if (htmlElement.getAttribute('data-bs-theme') === 'dark') {
                disableDarkMode();
            } else {
                enableDarkMode();
            }
        });
    }
    
    function enableDarkMode() {
        htmlElement.setAttribute('data-bs-theme', 'dark');
        localStorage.setItem('theme', 'dark');
        if (darkModeToggle) {
            darkModeToggle.innerHTML = '<i class="fas fa-sun"></i>';
            darkModeToggle.setAttribute('title', 'Switch to Light Mode');
        }
    }
    
    function disableDarkMode() {
        htmlElement.setAttribute('data-bs-theme', 'light');
        localStorage.setItem('theme', 'light');
        if (darkModeToggle) {
            darkModeToggle.innerHTML = '<i class="fas fa-moon"></i>';
            darkModeToggle.setAttribute('title', 'Switch to Dark Mode');
        }
    }

    // File upload preview for batch analyzer
    const fileInput = document.getElementById('log-file-upload');
    const fileList = document.getElementById('file-list');
    
    if (fileInput && fileList) {
        fileInput.addEventListener('change', updateFileList);
        
        function updateFileList() {
            fileList.innerHTML = '';
            
            if (fileInput.files.length > 0) {
                const listGroup = document.createElement('div');
                listGroup.className = 'list-group mt-3';
                
                for (let i = 0; i < fileInput.files.length; i++) {
                    const file = fileInput.files[i];
                    const item = document.createElement('div');
                    item.className = 'list-group-item d-flex justify-content-between align-items-center';
                    
                    const nameSpan = document.createElement('span');
                    nameSpan.textContent = file.name;
                    
                    const sizeSpan = document.createElement('span');
                    sizeSpan.className = 'badge bg-primary rounded-pill';
                    sizeSpan.textContent = formatFileSize(file.size);
                    
                    item.appendChild(nameSpan);
                    item.appendChild(sizeSpan);
                    listGroup.appendChild(item);
                }
                
                fileList.appendChild(listGroup);
            }
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    }
}); 