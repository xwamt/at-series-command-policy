const sensitiveNamePattern =
  /(?:^|[_-])(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)(?:$|[_-])/i;

export function isSensitiveIdentifier(identifier: string): boolean {
  return (
    identifier === '*' ||
    sensitiveNamePattern.test(identifier.replaceAll('.', '_'))
  );
}

const sensitiveDirectorySegments = new Set([
  '.ssh',
  '.aws',
  '.azure',
  '.kube',
  '.gnupg',
  '.docker',
  'credentials',
  'secrets',
  'serviceaccount',
  'service-account',
]);

const sensitiveProcPattern =
  /^\/proc\/(?:self|\d+)\/(?:environ|cmdline|maps|mem)$/;

export function isSensitivePath(path: string): boolean {
  const normalized = path.replaceAll('\\', '/').toLowerCase();
  const segments = normalized.split('/').filter(Boolean);
  const basename = segments.at(-1) ?? '';

  if (
    normalized === '/etc/shadow' ||
    normalized === '/etc/gshadow' ||
    sensitiveProcPattern.test(normalized)
  ) {
    return true;
  }
  if (segments.some((segment) => sensitiveDirectorySegments.has(segment))) {
    return true;
  }
  if (
    segments.some(
      (segment, index) =>
        segment === '.config' && segments[index + 1] === 'gcloud',
    )
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
