const sensitiveNamePattern =
  /(?:^|[_-])(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)(?:$|[_-])/i;

export function isSensitiveIdentifier(identifier: string): boolean {
  return (
    identifier === '*' ||
    sensitiveNamePattern.test(identifier.replaceAll('.', '_'))
  );
}

export function isSensitivePath(path: string): boolean {
  const normalized = path.replaceAll('\\', '/').toLowerCase();
  const segments = normalized.split('/').filter(Boolean);
  const basename = segments.at(-1) ?? '';

  if (
    normalized === '/etc/shadow' ||
    normalized === '/etc/gshadow' ||
    normalized.includes('/.ssh/') ||
    normalized.includes('/.aws/') ||
    normalized.includes('/.azure/') ||
    normalized.includes('/.kube/') ||
    normalized.includes('/.config/gcloud/') ||
    normalized.includes('/.docker/config.json') ||
    normalized.includes('/credentials/') ||
    normalized.includes('/secrets/') ||
    normalized.includes('/serviceaccount/') ||
    normalized.includes('/service-account/')
  ) {
    return true;
  }

  return (
    basename === '.env' ||
    basename.startsWith('.env.') ||
    basename === '.netrc' ||
    basename === '.npmrc' ||
    basename === '.pypirc' ||
    basename === '.bash_history' ||
    basename === '.zsh_history' ||
    basename === 'credentials' ||
    basename === 'known_hosts' ||
    /^id_(?:rsa|dsa|ecdsa|ed25519)$/.test(basename) ||
    /\.(?:pem|p12|pfx|key)$/.test(basename) ||
    sensitiveNamePattern.test(basename)
  );
}

export function isSensitiveHeader(header: string): boolean {
  const name = header.slice(0, Math.max(0, header.indexOf(':'))).trim();
  return /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)$/i.test(
    name,
  );
}

export function hasUrlCredentials(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.username.length > 0 || parsed.password.length > 0;
  } catch {
    return true;
  }
}
