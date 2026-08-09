import type { CollectionEntry } from 'astro:content';

export const isPublished = <T extends { data: { draft: boolean } }>(entry: T) =>
  !entry.data.draft;

export const newestPostsFirst = <T extends { data: { publishedAt: Date } }>(
  a: T,
  b: T,
) => b.data.publishedAt.valueOf() - a.data.publishedAt.valueOf();

export const newestAdvisoriesFirst = <T extends { data: { advisoryDate: Date } }>(
  a: T,
  b: T,
) => b.data.advisoryDate.valueOf() - a.data.advisoryDate.valueOf();

export const postUrl = (entry: CollectionEntry<'posts'>) =>
  `/posts/${entry.id}/`;

export const advisoryUrl = (entry: CollectionEntry<'advisories'>) =>
  `/advisories/${entry.id}/`;
