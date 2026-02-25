export type SecurityLevel = 'critical' | 'weak' | 'fair' | 'good' | 'strong';
export type Severity      = 'critical' | 'warning' | 'info';

export interface CheckResult {
  id:          string;
  label:       string;
  description: string;
  passed:      boolean;
  score:       number;
  max_score:   number;
  nist_ref:    string;
  severity:    Severity;
}

export interface AnalysisResult {
  password_length:      number;
  entropy_bits:         number;
  charset_size:         number;
  estimated_crack_time: string;
  score:                number;
  max_score:            number;
  percentage:           number;
  level:                SecurityLevel;
  level_label:          string;
  checks:               CheckResult[];
  recommendations:      string[];
}

export interface LevelConfig {
  color: string;
  glow:  string;
}

export const LEVEL_CONFIG: Record<SecurityLevel, LevelConfig> = {
  critical: { color: '#ff2d55', glow: 'rgba(255,45,85,0.35)'  },
  weak:     { color: '#ff6b35', glow: 'rgba(255,107,53,0.35)' },
  fair:     { color: '#ffd60a', glow: 'rgba(255,214,10,0.35)' },
  good:     { color: '#34c759', glow: 'rgba(52,199,89,0.30)'  },
  strong:   { color: '#00ff9f', glow: 'rgba(0,255,159,0.35)'  },
};

export const SEVERITY_ICON: Record<Severity, string> = {
  critical: '◈',
  warning:  '◆',
  info:     '◇',
};