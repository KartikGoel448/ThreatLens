/**
 * ThreatLens - Real Email Relay Trace & Hop Parser
 * 
 * Reconstructs the email relay chain strictly from RFC 822 Received headers:
 * - Chronological order: oldest (origin/submitter) -> intermediate relays -> newest (recipient)
 * - Real IP extraction and classification (Public vs Private/Reserved)
 * - Server-side IP geolocation (Approximate network location)
 * - Accurate transit delay calculation between consecutive valid timestamps
 * - Preserves "Unavailable" and "SMTP response unavailable" without generating fake data
 */

import { geolocateIp, classifyIp, type IpGeolocationData } from './ipGeolocation.js';
import type { RelayHop } from '../src/types.js';

export interface ParsedReceivedHop {
  raw: string;
  sendingHostname: string;
  receivingHostname: string;
  ip: string;
  timestampStr: string;
  parsedDate: Date | null;
  timezone: string;
  smtpInfo: string;
}

/**
 * Extracts individual components from a single RFC 822/2822 Received: header string.
 */
export function parseReceivedHeader(headerLine: string): ParsedReceivedHop {
  // Normalize whitespace
  const line = headerLine.replace(/\s+/g, ' ').trim();

  // Extract timestamp after semicolon ';' if present
  let timestampStr = 'Unavailable';
  let timezone = 'Unavailable';
  let parsedDate: Date | null = null;
  let bodyWithoutDate = line;

  const semiIndex = line.lastIndexOf(';');
  if (semiIndex !== -1) {
    const rawDatePart = line.slice(semiIndex + 1).trim();
    bodyWithoutDate = line.slice(0, semiIndex).trim();

    if (rawDatePart.length > 0) {
      timestampStr = rawDatePart;
      const d = new Date(rawDatePart);
      if (!isNaN(d.getTime())) {
        parsedDate = d;
      }
      // Extract timezone (e.g. +0000, -0700, UTC, EDT, PDT, etc.)
      const tzMatch = rawDatePart.match(/(?:([+-]\d{4})|(\b[A-Z]{3,4}\b))\s*(?:\([A-Z]{3,4}\))?$/);
      if (tzMatch) {
        timezone = tzMatch[0].trim();
      }
    }
  }

  // 1. Extract Sending Hostname ('from <host>')
  let sendingHostname = 'Unavailable';
  const fromMatch = bodyWithoutDate.match(/\bfrom\s+([^\s\(\)\[\];]+)/i);
  if (fromMatch && fromMatch[1] && fromMatch[1].toLowerCase() !== 'unknown') {
    sendingHostname = fromMatch[1].replace(/;$/, '').trim();
  }

  // 2. Extract Receiving Hostname ('by <host>')
  let receivingHostname = 'Unavailable';
  const byMatch = bodyWithoutDate.match(/\bby\s+([^\s\(\)\[\];]+)/i);
  if (byMatch && byMatch[1]) {
    receivingHostname = byMatch[1].replace(/;$/, '').trim();
  }

  // 3. Extract IP address
  // Check [IP] or (IP) or ([IP])
  let ip = 'Unavailable';
  const bracketIpMatch = bodyWithoutDate.match(/\[([0-9a-fA-F:\.]+)\]/);
  if (bracketIpMatch && bracketIpMatch[1]) {
    const candidate = bracketIpMatch[1].trim();
    if (isValidIp(candidate)) {
      ip = candidate;
    }
  }

  if (ip === 'Unavailable') {
    // Check parentheses: (host.com [1.2.3.4]) or (1.2.3.4)
    const parenIpMatch = bodyWithoutDate.match(/\(([^\)]+)\)/);
    if (parenIpMatch && parenIpMatch[1]) {
      const parenContent = parenIpMatch[1];
      const nestedIp = parenContent.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) ||
                       parenContent.match(/([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7})/);
      if (nestedIp && isValidIp(nestedIp[0])) {
        ip = nestedIp[0];
      }
    }
  }

  if (ip === 'Unavailable') {
    // Check any standalone IP in from/by clauses
    const standaloneIpv4 = bodyWithoutDate.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (standaloneIpv4 && isValidIp(standaloneIpv4[0])) {
      ip = standaloneIpv4[0];
    }
  }

  // 4. Extract SMTP protocol / TLS / ID info
  // RFC 2822: 'with PROTOCOL id ID'
  let smtpInfo = 'SMTP response unavailable';
  const withMatch = bodyWithoutDate.match(/\bwith\s+([a-zA-Z0-9_\-\.]+)/i);
  const idMatch = bodyWithoutDate.match(/\bid\s+([^\s;\(\)]+)/i);
  const tlsMatch = bodyWithoutDate.match(/\((version=[^\)]+)\)/i);

  if (withMatch || idMatch || tlsMatch) {
    const parts: string[] = [];
    if (withMatch) parts.push(withMatch[1].toUpperCase());
    if (idMatch) parts.push(`id ${idMatch[1]}`);
    if (tlsMatch) parts.push(tlsMatch[1]);
    smtpInfo = parts.join(' ');
  }

  return {
    raw: line,
    sendingHostname,
    receivingHostname,
    ip,
    timestampStr,
    parsedDate,
    timezone,
    smtpInfo,
  };
}

function isValidIp(str: string): boolean {
  if (!str) return false;
  // Basic IPv4 check
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(str)) {
    return str.split('.').every(n => parseInt(n, 10) <= 255);
  }
  // IPv6 check
  return str.includes(':') && str.length >= 2;
}

/**
 * Converts Latitude and Longitude to SVG (x, y) coordinates for viewBox="0 0 960 430".
 * Uses Equirectangular projection calibrated to the cybersecurity map landmasses.
 */
export function projectGeoToSvg(lat: number, lon: number): { x: number; y: number } {
  // Longitude: -180 to 180 maps to 20 to 940 (width 960)
  const normLon = (lon + 180) / 360;
  const x = Math.max(30, Math.min(930, normLon * 920 + 20));

  // Latitude: -65 to 75 maps to 400 to 30 (height 430)
  const clampedLat = Math.max(-65, Math.min(75, lat));
  const normLat = (75 - clampedLat) / 140;
  const y = Math.max(30, Math.min(400, normLat * 370 + 30));

  return {
    x: Math.round(x * 10) / 10,
    y: Math.round(y * 10) / 10,
  };
}

/**
 * Builds the complete, real data-driven Relay Trace from raw Received headers.
 */
export async function buildRealRelayTrace(
  rawReceivedHeaders: string[],
  fallbackSenderDomain: string,
  fallbackSenderIp?: string,
  fallbackDate?: string
): Promise<RelayHop[]> {
  // 1. If NO Received headers exist in message, create minimal honest single hop
  if (!rawReceivedHeaders || rawReceivedHeaders.length === 0) {
    const cleanIp = fallbackSenderIp && fallbackSenderIp !== 'Unavailable' ? fallbackSenderIp : 'Unavailable';
    const geo = await geolocateIp(cleanIp);
    const classification = classifyIp(cleanIp);

    const singleHop: RelayHop = {
      hopNumber: 1,
      name: 'Origin MTA / Submitter',
      role: 'SOURCE',
      host: fallbackSenderDomain || 'Unavailable',
      sendingHostname: 'Unavailable',
      ip: cleanIp,
      ipType: classification.ipType,
      location: geo.displayLocation,
      timestamp: fallbackDate || 'Unavailable',
      timezone: 'Unavailable',
      delayFromPreviousHop: 'Initial origin hop (No prior hop)',
      response: 'SMTP response unavailable',
      reason: 'Originating submission server (No Received transmission headers observed in email)',
      rawHeader: 'No Received headers available in submitted message',
      geolocation: {
        status: geo.status,
        country: geo.country,
        region: geo.region,
        city: geo.city,
        latitude: geo.latitude,
        longitude: geo.longitude,
        isp: geo.isp,
        asn: geo.asn,
        message: geo.message,
      },
      geo: typeof geo.latitude === 'number' && typeof geo.longitude === 'number'
        ? {
            ...projectGeoToSvg(geo.latitude, geo.longitude),
            label: fallbackSenderDomain || cleanIp,
          }
        : undefined,
    };

    return [singleHop];
  }

  // 2. Chronological Ordering:
  // RFC 822: In standard email transmission, MTAs PREPEND Received headers to the top.
  // rawReceivedHeaders[0] is newest (recipient-side), rawReceivedHeaders[last] is oldest (origin-side).
  // Reversing places them in chronological order: [oldest/origin -> intermediate -> newest/recipient]
  const chronologicalRaw = [...rawReceivedHeaders].reverse();
  const parsedHops = chronologicalRaw.map(parseReceivedHeader);

  // 3. Geolocate IPs concurrently and construct RelayHop objects
  const hops: RelayHop[] = [];

  for (let i = 0; i < parsedHops.length; i++) {
    const hop = parsedHops[i];
    const hopNum = i + 1;
    const isFirstHop = i === 0;
    const isLastHop = i === parsedHops.length - 1;

    // Determine hop display name and role based on transmission position
    let name: string;
    let role: 'SOURCE' | 'SUSPICIOUS' | 'WATCH' | 'TRUSTED' | 'DELIVERED';

    if (isFirstHop) {
      name = 'Origin MTA (Submission)';
      role = 'SOURCE';
    } else if (isLastHop) {
      name = 'Recipient MX Gateway';
      role = 'DELIVERED';
    } else {
      name = `Transit Relay Hop ${hopNum}`;
      role = 'WATCH';
    }

    // Server-side Geolocation
    const geoData: IpGeolocationData = await geolocateIp(hop.ip);
    const classification = classifyIp(hop.ip);

    // Calculate Transit Delay between consecutive hops
    let delayFromPreviousHop = 'Transit delay unavailable';
    let delayMs: number | undefined = undefined;

    if (isFirstHop) {
      delayFromPreviousHop = 'Initial hop (Transmission origin)';
    } else {
      const prevHop = parsedHops[i - 1];
      if (hop.parsedDate && prevHop.parsedDate) {
        const diffMs = hop.parsedDate.getTime() - prevHop.parsedDate.getTime();
        delayMs = diffMs;

        if (diffMs >= 0) {
          if (diffMs < 1000) {
            delayFromPreviousHop = '+<1s (Immediate relay)';
          } else if (diffMs < 60000) {
            delayFromPreviousHop = `+${Math.round(diffMs / 1000)}s transit delay`;
          } else {
            const mins = Math.floor(diffMs / 60000);
            const secs = Math.round((diffMs % 60000) / 1000);
            delayFromPreviousHop = `+${mins}m ${secs}s transit delay`;
          }
        } else {
          // Negative delay indicates MTA clock skew
          const skewSecs = Math.abs(Math.round(diffMs / 1000));
          delayFromPreviousHop = `Clock skew detected (${skewSecs}s discrepancy between MTA clocks)`;
        }
      } else {
        delayFromPreviousHop = 'Transit delay unavailable';
      }
    }

    // Hostname priority
    const hostDisplay = hop.receivingHostname !== 'Unavailable'
      ? hop.receivingHostname
      : hop.sendingHostname !== 'Unavailable'
      ? hop.sendingHostname
      : hop.ip !== 'Unavailable'
      ? hop.ip
      : 'Host unavailable';

    // Rationale description
    let reason = isFirstHop
      ? `Earliest observed relay hop in header chain. Received from '${hop.sendingHostname}' by '${hop.receivingHostname}'.`
      : isLastHop
      ? `Final recipient boundary MTA '${hop.receivingHostname}' accepting message.`
      : `Intermediate mail relay MTA '${hop.receivingHostname}' routing message towards destination.`;

    if (classification.isPrivateOrReserved) {
      reason += ` Note: Hop utilizes ${classification.reason}.`;
    }

    const relayHop: RelayHop = {
      hopNumber: hopNum,
      name,
      role,
      host: hostDisplay,
      sendingHostname: hop.sendingHostname,
      ip: hop.ip,
      ipType: classification.ipType,
      location: geoData.displayLocation,
      timestamp: hop.timestampStr,
      timezone: hop.timezone,
      delayFromPreviousHop,
      delayMs,
      response: hop.smtpInfo,
      reason,
      rawHeader: hop.raw,
      geolocation: {
        status: geoData.status,
        country: geoData.country,
        region: geoData.region,
        city: geoData.city,
        latitude: geoData.latitude,
        longitude: geoData.longitude,
        isp: geoData.isp,
        asn: geoData.asn,
        message: geoData.message,
      },
      // Only plot coordinates if successful public geolocation
      geo: typeof geoData.latitude === 'number' && typeof geoData.longitude === 'number'
        ? {
            ...projectGeoToSvg(geoData.latitude, geoData.longitude),
            label: hostDisplay,
          }
        : undefined,
    };

    hops.push(relayHop);
  }

  return hops;
}
