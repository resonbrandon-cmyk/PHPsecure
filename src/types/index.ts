export type VulnCategory = 
  | 'type-juggling'
  | 'object-injection'
  | 'file-inclusion'
  | 'command-injection'
  | 'variable-overwrite'
  | 'file-upload'
  | 'ssrf'
  | 'cve-spotlight';

export type PhpVersion = 'php5' | 'php7' | 'php8';

export interface ExploitPreset {
  id: string;
  name: string;
  description: string;
  payload: string;
  expectedOutcome: string;
  severity: 'Critical' | 'High' | 'Medium';
}

export interface ExecutionStep {
  step: number;
  phase: string;
  description: string;
  highlightCodeLine?: number;
  stateChange?: string;
  type: 'info' | 'vulnerability' | 'blocked' | 'success';
}

export interface VulnerabilityTopic {
  id: VulnCategory;
  title: string;
  cwe: string;
  summary: string;
  riskDescription: string;
  cvssScore: number;
  affectedVersions: string;
  rootCause: string;
  vulnerableSnippet: string;
  patchedSnippet: string;
  explanationPoints: string[];
  remediationSteps: string[];
  presets: ExploitPreset[];
  defaultPayload: string;
  simulateExecution: (input: string, version: PhpVersion, options?: Record<string, unknown>) => {
    isVulnerable: boolean;
    output: string;
    serverStatus: number;
    headers: Record<string, string>;
    executionTrace: ExecutionStep[];
    memoryState?: Record<string, string>;
    securityAlert?: string;
  };
}

export interface Challenge {
  id: string;
  title: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  category: VulnCategory;
  scenario: string;
  targetScript: string;
  goal: string;
  hint: string;
  initialInput: string;
  validateFlagOrPayload: (input: string) => { success: boolean; flag?: string; message: string };
  patchCode: string;
  patchExplanation: string;
}

export interface IniDirective {
  key: string;
  recommended: string;
  default: string;
  category: 'Code Execution' | 'File System' | 'Session & Cookies' | 'Information Leakage';
  description: string;
  riskIfMisconfigured: string;
}
