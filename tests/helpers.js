import { readFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
export const fx = (name) => new Uint8Array(readFileSync(join(here, '..', 'fixtures', name)));
export const inflate = async (data, max) => {
  const out = inflateSync(data, { maxOutputLength: max });
  return new Uint8Array(out);
};
export const root = join(here, '..');
