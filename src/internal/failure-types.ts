export type PolicyDomain = 'shell' | 'python' | 'sqlite' | 'mysql' | 'redis';

export type PolicyFailure =
  | 'analysis-unavailable'
  | 'initialization-failed'
  | 'parse-failed'
  | 'resource-limit-exceeded'
  | 'unknown-semantics';
