// The documentation site: Astro Starlight, published to GitHub Pages by the
// Docs workflow. Content arrives from three places at build time: the
// repository documents under docs/ (copied in by scripts/ingest.mjs), the
// reference pages generated from the code by scripts/gen_reference.py at the
// repository root, and the site-native pages in src/content/docs. The
// links validator fails the build on any broken internal link, and the
// llms-txt plugin emits llms.txt and llms-full.txt for AI consumption.
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightLinksValidator from 'starlight-links-validator';
import mdMirror from './src/integrations/md-mirror.mjs';

export default defineConfig({
  site: 'https://jagguvarma15.github.io',
  base: '/arrowhead',
  redirects: {
    '/SECURITY': '/arrowhead/security/',
    '/THREAT_MODEL': '/arrowhead/threat-model/',
    '/ARCHITECTURE': '/arrowhead/architecture/',
    '/DEPLOY': '/arrowhead/deployment/',
    '/INTEGRATIONS': '/arrowhead/integrations/',
  },
  integrations: [
    mermaid({ autoTheme: true }),
    starlight({
      title: 'Arrowhead',
      description: 'The fast, secure data plane for AI agents.',
      logo: {
        light: './src/assets/arrowhead.svg',
        dark: './src/assets/arrowhead-dark.svg',
      },
      favicon: '/favicon.svg',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/jagguvarma15/arrowhead',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      components: {
        Header: './src/components/Header.astro',
      },
      plugins: [starlightLlmsTxt(), starlightLinksValidator()],
      sidebar: [
        {
          label: 'Start',
          items: ['getting-started', 'integrations'],
        },
        {
          label: 'Reference',
          items: [
            'reference/tools',
            'reference/configuration',
            'reference/capabilities',
          ],
        },
        {
          label: 'Security',
          items: ['security', 'threat-model'],
        },
        {
          label: 'Operate',
          items: ['architecture', 'deployment'],
        },
        {
          label: 'Examples',
          items: ['examples/docs-rag', 'examples/coding-agent'],
        },
        {
          label: 'Project',
          items: ['contributing', 'faq'],
        },
      ],
    }),
    mdMirror(),
  ],
});
