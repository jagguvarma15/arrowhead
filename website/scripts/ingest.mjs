// Copies the repository documents into the site's content collection before a
// build. The repo files under docs/ stay the single source of truth and carry
// no frontmatter; this script derives the frontmatter title from each H1,
// strips the H1 (Starlight renders the title itself), and writes the result
// under a clean lowercase slug. The copies are gitignored: they exist only
// during a build.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoDocs = join(here, '..', '..', 'docs');
const outDir = join(here, '..', 'src', 'content', 'docs');

const PAGES = [
  {
    source: 'SECURITY.md',
    target: 'security.md',
    description: 'Each mitigation mapped to the vulnerability class it closes.',
  },
  {
    source: 'THREAT_MODEL.md',
    target: 'threat-model.md',
    description: 'The attack surface per tool and what is out of scope.',
  },
  {
    source: 'ARCHITECTURE.md',
    target: 'architecture.md',
    description: 'The request flow from auth to the audit log, and the module layout.',
  },
  {
    source: 'DEPLOY.md',
    target: 'deployment.md',
    description: 'The step-by-step runbook for a live reference deployment.',
  },
];

mkdirSync(outDir, { recursive: true });
for (const page of PAGES) {
  const raw = readFileSync(join(repoDocs, page.source), 'utf8');
  const match = raw.match(/^# (.+)\n/);
  if (!match) {
    throw new Error(`${page.source} has no H1 to derive a title from`);
  }
  const title = match[1];
  const body = raw.slice(match[0].length).replace(/^\n+/, '');
  const frontmatter = [
    '---',
    `title: "${title}"`,
    `description: "${page.description}"`,
    '---',
    '',
  ].join('\n');
  writeFileSync(join(outDir, page.target), frontmatter + body);
}
