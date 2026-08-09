import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    publishedAt: z.coerce.date(),
    updatedAt: z.coerce.date().optional(),
    eyebrow: z.string().default('Post'),
    readingTime: z.string(),
    tags: z.array(z.string()).default([]),
    featured: z.boolean().default(false),
    draft: z.boolean().default(false),
  }),
});

const advisories = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/advisories' }),
  schema: z.object({
    title: z.string(),
    summary: z.string(),
    advisoryDate: z.coerce.date(),
    advisoryDateLabel: z.string().optional(),
    updatedAt: z.coerce.date().optional(),
    identifier: z.string(),
    vendor: z.string(),
    product: z.string(),
    priority: z.enum(['act-now', 'high', 'watch']),
    status: z.string(),
    dueDate: z.coerce.date().optional(),
    kev: z.boolean().default(false),
    cwes: z.array(z.string()).default([]),
    technologies: z.array(z.string()).default([]),
    weaknesses: z.array(z.string()).default([]),
    impacts: z.array(z.string()).default([]),
    evidence: z.array(z.string()).default([]),
    actions: z.array(z.string()).default([]),
    eli5: z.string(),
    flow: z.array(
      z.object({
        label: z.string(),
        detail: z.string(),
      }),
    ).min(3).max(5),
    sourceLinks: z.array(
      z.object({
        label: z.string(),
        url: z.url(),
      }),
    ),
    draft: z.boolean().default(false),
  }),
});

export const collections = { posts, advisories };
