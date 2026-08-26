import {
  createScanner,
  SyntaxKind,
} from 'typescript/unstable/ast';

function scanTokens(sourceText) {
  const scanner = createScanner(true, undefined, sourceText);
  const tokens = [];

  for (
    let kind = scanner.scan();
    kind !== SyntaxKind.EndOfFile;
    kind = scanner.scan()
  ) {
    tokens.push({
      kind,
      start: scanner.getTokenStart(),
      end: scanner.getTokenEnd(),
      value: scanner.getTokenValue(),
    });
  }

  return tokens;
}

function statementStartsWithImportOrExport(tokens, beforeIndex) {
  for (let index = beforeIndex; index >= 0; index -= 1) {
    const kind = tokens[index].kind;

    if (kind === SyntaxKind.SemicolonToken) {
      return false;
    }

    if (
      kind === SyntaxKind.ImportKeyword ||
      kind === SyntaxKind.ExportKeyword
    ) {
      return true;
    }
  }

  return false;
}

function isModuleSpecifier(tokens, index) {
  const previous = tokens[index - 1];
  const beforePrevious = tokens[index - 2];

  if (previous?.kind === SyntaxKind.FromKeyword) {
    return statementStartsWithImportOrExport(tokens, index - 2);
  }

  if (previous?.kind === SyntaxKind.ImportKeyword) {
    return true;
  }

  if (previous?.kind !== SyntaxKind.OpenParenToken) {
    return false;
  }

  if (beforePrevious?.kind === SyntaxKind.ImportKeyword) {
    return true;
  }

  return (
    beforePrevious?.value === 'require' &&
    statementStartsWithImportOrExport(tokens, index - 3)
  );
}

export function rewriteCjsModuleSpecifiers(sourceText, specifierMap) {
  const tokens = scanTokens(sourceText);
  const replacements = [];

  for (const [index, token] of tokens.entries()) {
    if (
      token.kind !== SyntaxKind.StringLiteral ||
      !/^\.{1,2}\//.test(token.value) ||
      !isModuleSpecifier(tokens, index)
    ) {
      continue;
    }

    const mappedSpecifier = specifierMap.get(token.value);
    if (mappedSpecifier === undefined) {
      continue;
    }

    const quote = sourceText[token.start];
    replacements.push({
      start: token.start,
      end: token.end,
      text: `${quote}${mappedSpecifier}${quote}`,
    });
  }

  let rewritten = sourceText;
  for (const replacement of replacements.reverse()) {
    rewritten =
      rewritten.slice(0, replacement.start) +
      replacement.text +
      rewritten.slice(replacement.end);
  }

  return rewritten;
}
