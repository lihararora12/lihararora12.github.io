import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import { advisoryUrl, postUrl, isPublished } from '../lib/content';

export async function GET(context) {
  const posts = (await getCollection('posts')).filter(isPublished);
  const advisories = (await getCollection('advisories')).filter(isPublished);

  const items = [
    ...posts.map((entry) => ({
      title: entry.data.title,
      description: entry.data.description,
      pubDate: entry.data.publishedAt,
      link: postUrl(entry),
      categories: entry.data.tags,
    })),
    ...advisories.map((entry) => ({
      title: `${entry.data.identifier}: ${entry.data.title}`,
      description: entry.data.summary,
      pubDate: entry.data.advisoryDate,
      link: advisoryUrl(entry),
      categories: ['Advisory', entry.data.vendor, entry.data.status],
    })),
  ].sort((a, b) => b.pubDate.valueOf() - a.pubDate.valueOf());

  return rss({
    title: 'vuln.management',
    description: 'Posts, advisories, playbooks, and memes for modern vulnerability management.',
    site: context.site,
    items,
    customData: '<language>en-us</language>',
  });
}
