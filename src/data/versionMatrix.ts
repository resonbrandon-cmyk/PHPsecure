export interface VersionQuirk {
  id: string;
  category: string;
  expression: string;
  php5: string;
  php7: string;
  php8: string;
  securityImpact: string;
  explanation: string;
}

export const PHP_VERSION_MATRIX: VersionQuirk[] = [
  {
    id: 'string-number-zero',
    category: 'Type Juggling',
    expression: '"foo" == 0',
    php5: 'true',
    php7: 'true',
    php8: 'false',
    securityImpact: 'Critical (Auth Bypass)',
    explanation: 'In PHP 5 and 7, non-numeric strings cast to int(0), making any arbitrary string equal to numeric 0. In PHP 8, numeric comparisons compare as strings if one side is non-numeric.'
  },
  {
    id: 'string-prefix-number',
    category: 'Type Juggling',
    expression: '"42admin" == 42',
    php5: 'true',
    php7: 'true',
    php8: 'false',
    securityImpact: 'High (IDOR & Privilege Escalation)',
    explanation: 'PHP 5/7 extracted leading digits and ignored trailing characters. PHP 8 evaluates this strictly as false.'
  },
  {
    id: 'magic-hash-equality',
    category: 'Type Juggling',
    expression: '"0e12345" == "0e99999"',
    php5: 'true (0 == 0)',
    php7: 'true (0 == 0)',
    php8: 'true (0 == 0)',
    securityImpact: 'Critical (Password & Token Bypass)',
    explanation: 'Both sides match scientific notation (0 * 10^x). Both evaluate to 0.0. Still true in PHP 8 if both strings contain solely digits after 0e!'
  },
  {
    id: 'null-byte-truncation',
    category: 'File Inclusion & FS',
    expression: 'include("page.php\\0.html")',
    php5: 'Reads "page.php" (PHP < 5.3.4)',
    php7: 'Fatal Error / Rejected',
    php8: 'ValueError: Path cannot contain null bytes',
    securityImpact: 'High (Bypassing File Suffix Append)',
    explanation: 'C-string termination vulnerability where null byte \\0 terminated filename before the server-appended extension. Fully patched in modern PHP.'
  },
  {
    id: 'assert-string-code-eval',
    category: 'Command & Code Eval',
    expression: 'assert("phpinfo()")',
    php5: 'Executes phpinfo()',
    php7: 'Executes phpinfo() (Deprecated)',
    php8: 'Fatal Error: assert() takes boolean only',
    securityImpact: 'Critical (Hidden RCE)',
    explanation: 'In PHP 5 and 7, passing a string to assert() treated it as PHP code to evaluate. Developers using assert() as unit test checks inadvertently exposed arbitrary code execution sinks.'
  },
  {
    id: 'preg-replace-eval-modifier',
    category: 'Command & Code Eval',
    expression: 'preg_replace("/(.*)/e", "\\1", $input)',
    php5: 'Executes replacement as PHP code',
    php7: 'Removed (Fatal E_ERROR in PHP 7.0+)',
    php8: 'Removed',
    securityImpact: 'Critical (Regex RCE)',
    explanation: 'The infamous /e modifier in PCRE functions evaluated the replacement string as PHP code, making regular expression matchers dangerous execution sinks.'
  },
  {
    id: 'unserialize-allowed-classes',
    category: 'Object Deserialization',
    expression: 'unserialize($data, ["allowed_classes" => false])',
    php5: 'Not Supported (Instantiates all classes)',
    php7: 'Supported (Safe scalar DTO mode)',
    php8: 'Supported (Recommended baseline)',
    securityImpact: 'Critical (POP Chain Mitigation)',
    explanation: 'PHP 7.0 introduced the allowed_classes parameter. In PHP 5, all deserialized classes in the symbol table would instantiate and invoke __wakeup() without restrictions.'
  },
  {
    id: 'create-function-eval',
    category: 'Code Evaluation',
    expression: 'create_function("", $code)',
    php5: 'Active (Internally invokes eval)',
    php7: 'Deprecated in 7.2',
    php8: 'Removed in PHP 8.0',
    securityImpact: 'High (Insecure dynamic lambda)',
    explanation: 'Historically used to create anonymous functions, create_function() internally passed the body directly to Zend eval(), creating frequent code injection bugs.'
  },
  {
    id: 'cve-2024-4577-cgi',
    category: 'Argument Injection',
    expression: 'Windows CGI Soft-Hyphen (%ad)',
    php5: 'Vulnerable in CGI mode',
    php7: 'Vulnerable in CGI mode',
    php8: 'Patched in 8.1.29, 8.2.20, 8.3.8',
    securityImpact: 'Critical (Unauthenticated RCE)',
    explanation: 'Windows Best-Fit encoding mapped 0xAD soft hyphen to 0x2D (-), bypassing CGI argument check and allowing arbitrary runtime INI flags injection.'
  }
];
