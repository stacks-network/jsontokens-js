import { fromByteArray, toByteArray } from 'base64-js';

export function pad(base64: string): string {
  return `${base64}${'='.repeat(4 - (base64.length % 4 || 4))}`;
}

export function escape(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function unescape(base64Url: string): string {
  return pad(base64Url).replace(/-/g, '+').replace(/_/g, '/');
}

export function encode(base64: string): string {
  return escape(fromByteArray(new TextEncoder().encode(base64)));
}

export function decode(base64Url: string): string {
  return new TextDecoder().decode(toByteArray(pad(unescape(base64Url))));
}
