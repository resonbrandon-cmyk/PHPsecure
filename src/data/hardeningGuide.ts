import { IniDirective } from '../types';

export const INI_HARDENING_DIRECTIVES: IniDirective[] = [
  {
    key: 'allow_url_include',
    recommended: 'Off',
    default: 'Off',
    category: 'Code Execution',
    description: 'Enables the use of URL-aware fopen wrappers with include, include_once, require, require_once.',
    riskIfMisconfigured: 'Setting to On enables immediate Remote File Inclusion (RFI) via php://input, data://, and remote HTTP URLs, leading to instantaneous Remote Code Execution.'
  },
  {
    key: 'allow_url_fopen',
    recommended: 'Off',
    default: 'On',
    category: 'File System',
    description: 'Enables URL-aware fopen wrappers that allow accessing URL object files via FTP, HTTP, etc.',
    riskIfMisconfigured: 'Leaving On allows file_get_contents($url) to trigger Server-Side Request Forgery (SSRF) and cloud metadata theft.'
  },
  {
    key: 'disable_functions',
    recommended: 'exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source',
    default: '',
    category: 'Code Execution',
    description: 'Disables dangerous internal functions that interface directly with OS processes and the system shell.',
    riskIfMisconfigured: 'Leaving empty means any web shell or command injection bug has full access to the underlying OS command shell.'
  },
  {
    key: 'open_basedir',
    recommended: '/var/www/html/:/tmp/',
    default: 'none',
    category: 'File System',
    description: 'Limits the files that can be accessed by PHP to the specified directory-tree, including the file itself.',
    riskIfMisconfigured: 'Without open_basedir, any Local File Inclusion (LFI) or file read bug can read /etc/passwd, /etc/shadow, and system-wide files.'
  },
  {
    key: 'display_errors',
    recommended: 'Off',
    default: 'On (Dev) / Off (Prod)',
    category: 'Information Leakage',
    description: 'Determines whether errors should be printed to the screen as part of the output or if they should be hidden.',
    riskIfMisconfigured: 'Setting to On leaks full absolute server paths, SQL query syntax errors, and stack traces directly to potential attackers.'
  },
  {
    key: 'expose_php',
    recommended: 'Off',
    default: 'On',
    category: 'Information Leakage',
    description: 'Decides whether PHP may expose the fact that it is installed on the server (e.g. adding the signature to the Web server header X-Powered-By: PHP/x.x.x).',
    riskIfMisconfigured: 'Setting to On broadcasts exact patch version to scanners and attackers, making targeted CVE exploitation effortless.'
  },
  {
    key: 'session.cookie_httponly',
    recommended: '1',
    default: '0',
    category: 'Session & Cookies',
    description: 'Marks the cookie as accessible only through the HTTP protocol. Javascript cannot access document.cookie.',
    riskIfMisconfigured: 'If 0, any Cross-Site Scripting (XSS) vulnerability will allow instant theft of the PHP PHPSESSID session token.'
  },
  {
    key: 'session.cookie_secure',
    recommended: '1',
    default: '0',
    category: 'Session & Cookies',
    description: 'Specifies whether cookies should only be sent over secure HTTPS connections.',
    riskIfMisconfigured: 'If 0, session identifiers are transmitted in plaintext over insecure Wi-Fi / HTTP networks.'
  },
  {
    key: 'session.use_strict_mode',
    recommended: '1',
    default: '0',
    category: 'Session & Cookies',
    description: 'Prevents session fixation attacks by rejecting uninitialized user-supplied session IDs.',
    riskIfMisconfigured: 'If 0, attackers can set an arbitrary session ID on the victim and wait for them to log in (Session Fixation).'
  }
];
