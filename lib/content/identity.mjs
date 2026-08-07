import { createHash } from 'node:crypto';
export const contentId = ({ text, source = {}, surface = {} }) => `sha256:${createHash('sha256').update([text, source.file ?? '', surface.route ?? '', surface.type ?? ''].join('\0')).digest('hex')}`;
export const textDigest = (text) => `sha256:${createHash('sha256').update(text).digest('hex')}`;
