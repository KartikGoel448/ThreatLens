/**
 * ThreatLens Email Content Extractor
 *
 * Extracts structured content from raw RFC 822/2822 messages:
 * - Subject
 * - From address
 * - Return-Path when available
 * - plain-text body
 * - HTML body when available (safely stripped of markup to readable text if plain-text is absent)
 * - extracted URLs and surrounding visible text context
 *
 * Honors the strict boundary: No hallucination, no fabricated body content.
 */

export interface ExtractedUrlInfo {
  url: string;
  surroundingText?: string;
}

export interface ExtractedEmailContent {
  subject: string;
  from: string;
  returnPath?: string;
  plainTextBody: string;
  htmlBody?: string;
  bodyAvailable: boolean;
  extractedUrls: ExtractedUrlInfo[];
}

/**
 * Decode Quoted-Printable encoded string
 */
function decodeQuotedPrintable(input: string): string {
  // Soft line breaks (equals sign at the end of line)
  const withoutSoftBreaks = input.replace(/=\r?\n/g, '');
  // Hex byte representations =XX
  return withoutSoftBreaks.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch {
      return _;
    }
  });
}

/**
 * Decode Base64 string safely
 */
function decodeBase64Safe(input: string): string {
  try {
    const clean = input.replace(/\s+/g, '');
    return Buffer.from(clean, 'base64').toString('utf-8');
  } catch {
    return input;
  }
}

/**
 * Decode common HTML entities to readable plain text
 */
function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, dec) => {
      try {
        return String.fromCharCode(parseInt(dec, 10));
      } catch {
        return _;
      }
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      try {
        return String.fromCharCode(parseInt(hex, 16));
      } catch {
        return _;
      }
    });
}

/**
 * Convert HTML to readable plain text without tags
 */
export function htmlToPlainText(html: string): string {
  if (!html) return '';

  let text = html;
  // Remove script and style elements with their contents
  text = text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  text = text.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
  text = text.replace(/<!--[\s\S]*?-->/g, '');

  // Convert line breaks and paragraph ends to newlines
  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/(p|div|tr|h[1-6]|li)>/gi, '\n');
  text = text.replace(/<li[^>]*>/gi, '• ');

  // Strip remaining tags
  text = text.replace(/<[^>]+>/g, ' ');

  // Decode entities
  text = decodeHtmlEntities(text);

  // Normalize spaces and consecutive newlines
  text = text.replace(/[ \t]+/g, ' ');
  text = text.replace(/\n\s*\n\s*\n+/g, '\n\n');

  return text.trim();
}

/**
 * Extracts URLs and their anchor text or surrounding text context from text/HTML
 */
export function extractUrlsWithContext(rawText: string, html?: string): ExtractedUrlInfo[] {
  const map = new Map<string, ExtractedUrlInfo>();

  // 1. If HTML is available, extract anchor tags with their visible link text
  if (html) {
    const anchorRegex = /<a\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    while ((match = anchorRegex.exec(html)) !== null) {
      const url = match[1].trim();
      const rawAnchor = match[2];
      const anchorText = decodeHtmlEntities(rawAnchor.replace(/<[^>]+>/g, '').trim());
      if (url && !map.has(url)) {
        map.set(url, {
          url,
          surroundingText: anchorText.length > 0 ? anchorText.slice(0, 120) : undefined,
        });
      }
    }
  }

  // 2. Extract plain URLs from rawText / combined text
  const urlRegex = /https?:\/\/[^\s"'<>\)]+/gi;
  let textMatch: RegExpExecArray | null;
  while ((textMatch = urlRegex.exec(rawText)) !== null) {
    const url = textMatch[0].trim();
    if (!map.has(url)) {
      // Get ±60 characters surrounding the URL
      const start = Math.max(0, textMatch.index - 50);
      const end = Math.min(rawText.length, textMatch.index + url.length + 50);
      const contextSnippet = rawText
        .slice(start, end)
        .replace(/\s+/g, ' ')
        .trim();

      map.set(url, {
        url,
        surroundingText: contextSnippet.length > url.length ? contextSnippet.slice(0, 140) : undefined,
      });
    }
  }

  return Array.from(map.values());
}

/**
 * Main extractor: extracts subject, from, return-path, plain-text body, HTML body, and URLs
 */
export function extractEmailContent(rawInput: string): ExtractedEmailContent {
  const normalized = rawInput.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  let headerBlock = normalized;
  let bodyBlock = '';

  const headerEnd = normalized.indexOf('\n\n');
  if (headerEnd !== -1) {
    headerBlock = normalized.slice(0, headerEnd);
    bodyBlock = normalized.slice(headerEnd + 2);
  }

  // Handle folded lines for headers
  const headerLines = headerBlock.split('\n');
  const unfolded: string[] = [];
  for (const line of headerLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfolded.push(line);
    }
  }

  const headers = new Map<string, string>();
  for (const line of unfolded) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();
      headers.set(key, val);
    }
  }

  const subject = headers.get('subject') || 'No Subject';
  const from = headers.get('from') || 'unknown@example.com';
  const returnPath = headers.get('return-path')?.replace(/[<>]/g, '').trim();

  let plainTextBody = '';
  let htmlBody: string | undefined = undefined;

  const contentTypeHeader = headers.get('content-type') || '';
  const transferEncodingHeader = headers.get('content-transfer-encoding')?.toLowerCase() || '';

  // Check if MIME multipart
  const boundaryMatch = contentTypeHeader.match(/boundary=["']?([^"';]+)["']?/i);
  if (boundaryMatch && boundaryMatch[1]) {
    const boundary = boundaryMatch[1].trim();
    const parts = bodyBlock.split(new RegExp(`--${boundary}(?:--)?`));

    for (const part of parts) {
      const trimmedPart = part.trim();
      if (!trimmedPart) continue;

      const partHeaderEnd = trimmedPart.indexOf('\n\n');
      if (partHeaderEnd === -1) continue;

      const partHeaders = trimmedPart.slice(0, partHeaderEnd).toLowerCase();
      let partBody = trimmedPart.slice(partHeaderEnd + 2);

      const partEncoding = partHeaders.includes('content-transfer-encoding: base64')
        ? 'base64'
        : partHeaders.includes('content-transfer-encoding: quoted-printable')
        ? 'quoted-printable'
        : '';

      if (partEncoding === 'base64') {
        partBody = decodeBase64Safe(partBody);
      } else if (partEncoding === 'quoted-printable') {
        partBody = decodeQuotedPrintable(partBody);
      }

      if (partHeaders.includes('text/plain')) {
        plainTextBody = (plainTextBody ? plainTextBody + '\n\n' : '') + partBody.trim();
      } else if (partHeaders.includes('text/html')) {
        htmlBody = (htmlBody ? htmlBody + '\n\n' : '') + partBody.trim();
      }
    }
  } else {
    // Non-multipart single body
    let decodedBody = bodyBlock;
    if (transferEncodingHeader === 'base64') {
      decodedBody = decodeBase64Safe(bodyBlock);
    } else if (transferEncodingHeader === 'quoted-printable') {
      decodedBody = decodeQuotedPrintable(bodyBlock);
    }

    if (contentTypeHeader.toLowerCase().includes('text/html') || /<html\b|<body\b|<p\b/i.test(decodedBody)) {
      htmlBody = decodedBody;
    } else {
      plainTextBody = decodedBody;
    }
  }

  // If plain-text body is empty but HTML is available, safely convert HTML to readable plain text
  if (!plainTextBody.trim() && htmlBody && htmlBody.trim()) {
    plainTextBody = htmlToPlainText(htmlBody);
  }

  const finalPlainText = plainTextBody.trim();
  const bodyAvailable = finalPlainText.length > 0;

  // Extract all URLs and contextual anchor text
  const extractedUrls = extractUrlsWithContext(rawInput, htmlBody);

  return {
    subject,
    from,
    returnPath,
    plainTextBody: finalPlainText,
    htmlBody: htmlBody?.trim() ? htmlBody.trim() : undefined,
    bodyAvailable,
    extractedUrls,
  };
}
