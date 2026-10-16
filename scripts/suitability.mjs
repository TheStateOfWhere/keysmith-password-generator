// Extract complete words, not metadata or pieces of hyphenated/apostrophe forms.
export function sensitiveWords(annotations) {
  const words = annotations.split(/\r?\n/).filter(line => /\((?:vulgar|offensive)-\d+\)/.test(line)).flatMap(line => {
    const body = line.slice(line.indexOf(':') + 1).split('#')[0].replace(/<[^>]*>/g, '').replace(/\((?:vulgar|offensive)-\d+\)/g, '');
    return body.match(/[A-Za-z][A-Za-z'-]*/g) ?? [];
  });
  return [...new Set(words.filter(w => /^[a-z]{4,12}$/.test(w) && !/[lio]/i.test(w)))].sort();
}
