// After a build, mirrors every plain-markdown content page into the output
// directory as <slug>.md, so agents and scripts can read a page's raw
// markdown by appending .md to its URL path. MDX pages are composed from
// components and are not mirrored; llms-full.txt covers the whole site.
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export default function mdMirror() {
  return {
    name: 'md-mirror',
    hooks: {
      'astro:build:done': ({ dir, logger }) => {
        const outDir = fileURLToPath(dir);
        const contentDir = join(
          dirname(fileURLToPath(import.meta.url)),
          '..',
          'content',
          'docs',
        );
        let mirrored = 0;
        const walk = (directory) => {
          for (const entry of readdirSync(directory, { withFileTypes: true })) {
            const path = join(directory, entry.name);
            if (entry.isDirectory()) {
              walk(path);
              continue;
            }
            if (!entry.name.endsWith('.md')) continue;
            const slug = relative(contentDir, path).replace(/\.md$/, '');
            const raw = readFileSync(path, 'utf8');
            const match = raw.match(/^---\n([\s\S]*?)\n---\n/);
            let body = raw;
            let heading = '';
            if (match) {
              body = raw.slice(match[0].length);
              const title = match[1].match(/^title:\s*"?([^"\n]+)"?$/m);
              if (title) heading = `# ${title[1]}\n\n`;
            }
            const target = join(outDir, `${slug}.md`);
            mkdirSync(dirname(target), { recursive: true });
            writeFileSync(target, heading + body.replace(/^\n+/, ''));
            mirrored += 1;
          }
        };
        walk(contentDir);
        logger.info(`mirrored ${mirrored} markdown pages`);
      },
    },
  };
}
