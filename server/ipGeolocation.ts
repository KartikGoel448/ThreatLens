/**
 * ThreatLens - Real IP Geolocation & Classification Service
 * 
 * Complies with ThreatLens Trust & Geolocation Model:
 * 1. Identifies private, reserved, loopback, link-local, and documentation IP ranges.
 * 2. Strictly bypasses public geolocation queries for private/reserved IPs.
 * 3. Queries authoritative free HTTPS geolocation services for public IPs with zero API keys required.
 * 4. Explicitly labels results as approximate network geolocation.
 * 5. Does not fabricate coordinates or countries when geolocation fails.
 */

export interface IpClassification {
  isPrivateOrReserved: boolean;
  ipType: 'PUBLIC' | 'PRIVATE' | 'RESERVED' | 'DOCUMENTATION' | 'LOOPBACK' | 'UNAVAILABLE';
  reason: string;
}

export interface IpGeolocationData {
  status: 'SUCCESS' | 'PRIVATE_RESERVED' | 'UNAVAILABLE';
  ipType: 'PUBLIC' | 'PRIVATE' | 'RESERVED' | 'DOCUMENTATION' | 'LOOPBACK' | 'UNAVAILABLE';
  displayLocation: string;
  country?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  isp?: string | null;
  asn?: string | null;
  message?: string;
}

// In-memory cache for fast lookup and rate-limit prevention
const geoCache = new Map<string, IpGeolocationData>();

/**
 * Classifies whether an IP is private, reserved, loopback, documentation, or public.
 */
export function classifyIp(ip: string): IpClassification {
  if (!ip || typeof ip !== 'string' || ip.trim().length === 0 || ip === 'Unavailable') {
    return {
      isPrivateOrReserved: true,
      ipType: 'UNAVAILABLE',
      reason: 'No valid IP address specified',
    };
  }

  const cleanIp = ip.trim().replace(/^\[|\]$/g, '');

  // IPv4 Classification
  const ipv4Match = cleanIp.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const a = parseInt(ipv4Match[1], 10);
    const b = parseInt(ipv4Match[2], 10);
    const c = parseInt(ipv4Match[3], 10);
    const d = parseInt(ipv4Match[4], 10);

    if (a > 255 || b > 255 || c > 255 || d > 255) {
      return {
        isPrivateOrReserved: true,
        ipType: 'UNAVAILABLE',
        reason: 'Invalid IPv4 octet value',
      };
    }

    // 127.0.0.0/8 - Loopback
    if (a === 127) {
      return {
        isPrivateOrReserved: true,
        ipType: 'LOOPBACK',
        reason: 'Loopback address (127.0.0.0/8)',
      };
    }

    // 10.0.0.0/8 - RFC 1918 Private
    if (a === 10) {
      return {
        isPrivateOrReserved: true,
        ipType: 'PRIVATE',
        reason: 'RFC 1918 Private network (10.0.0.0/8)',
      };
    }

    // 172.16.0.0/12 - RFC 1918 Private
    if (a === 172 && b >= 16 && b <= 31) {
      return {
        isPrivateOrReserved: true,
        ipType: 'PRIVATE',
        reason: 'RFC 1918 Private network (172.16.0.0/12)',
      };
    }

    // 192.168.0.0/16 - RFC 1918 Private
    if (a === 192 && b === 168) {
      return {
        isPrivateOrReserved: true,
        ipType: 'PRIVATE',
        reason: 'RFC 1918 Private network (192.168.0.0/16)',
      };
    }

    // 169.254.0.0/16 - Link-Local (APIPA / RFC 3927)
    if (a === 169 && b === 254) {
      return {
        isPrivateOrReserved: true,
        ipType: 'RESERVED',
        reason: 'Link-Local address (169.254.0.0/16)',
      };
    }

    // 100.64.0.0/10 - Carrier-Grade NAT (RFC 6598)
    if (a === 100 && b >= 64 && b <= 127) {
      return {
        isPrivateOrReserved: true,
        ipType: 'RESERVED',
        reason: 'Carrier-Grade NAT (100.64.0.0/10 RFC 6598)',
      };
    }

    // RFC 5737 Documentation Ranges (TEST-NET-1, 2, 3)
    if (a === 192 && b === 0 && c === 2) {
      return {
        isPrivateOrReserved: true,
        ipType: 'DOCUMENTATION',
        reason: 'RFC 5737 Documentation block TEST-NET-1 (192.0.2.0/24)',
      };
    }
    if (a === 198 && b === 51 && c === 100) {
      return {
        isPrivateOrReserved: true,
        ipType: 'DOCUMENTATION',
        reason: 'RFC 5737 Documentation block TEST-NET-2 (198.51.100.0/24)',
      };
    }
    if (a === 203 && b === 0 && c === 113) {
      return {
        isPrivateOrReserved: true,
        ipType: 'DOCUMENTATION',
        reason: 'RFC 5737 Documentation block TEST-NET-3 (203.0.113.0/24)',
      };
    }

    // 0.0.0.0/8 - Broadcast / Source
    if (a === 0) {
      return {
        isPrivateOrReserved: true,
        ipType: 'RESERVED',
        reason: 'Reserved current network (0.0.0.0/8)',
      };
    }

    // 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved)
    if (a >= 224) {
      return {
        isPrivateOrReserved: true,
        ipType: 'RESERVED',
        reason: 'Multicast or future reserved block (224.0.0.0/4)',
      };
    }

    return {
      isPrivateOrReserved: false,
      ipType: 'PUBLIC',
      reason: 'Public routable IPv4 address',
    };
  }

  // IPv6 Classification
  const lowerV6 = cleanIp.toLowerCase();
  if (lowerV6.includes(':')) {
    if (lowerV6 === '::1' || lowerV6 === '0:0:0:0:0:0:0:1') {
      return {
        isPrivateOrReserved: true,
        ipType: 'LOOPBACK',
        reason: 'IPv6 Loopback (::1)',
      };
    }
    if (lowerV6.startsWith('fe80:')) {
      return {
        isPrivateOrReserved: true,
        ipType: 'RESERVED',
        reason: 'IPv6 Link-Local (fe80::/10)',
      };
    }
    if (lowerV6.startsWith('fc') || lowerV6.startsWith('fd')) {
      return {
        isPrivateOrReserved: true,
        ipType: 'PRIVATE',
        reason: 'IPv6 Unique Local Address (fc00::/7)',
      };
    }
    if (lowerV6.startsWith('2001:db8:') || lowerV6.startsWith('2001:0db8:')) {
      return {
        isPrivateOrReserved: true,
        ipType: 'DOCUMENTATION',
        reason: 'IPv6 Documentation prefix (RFC 3849)',
      };
    }

    return {
      isPrivateOrReserved: false,
      ipType: 'PUBLIC',
      reason: 'Public routable IPv6 address',
    };
  }

  return {
    isPrivateOrReserved: true,
    ipType: 'UNAVAILABLE',
    reason: 'Unrecognized IP format',
  };
}

/**
 * Performs server-side approximate IP geolocation.
 * - For private/reserved IPs: returns immediately with "Private/Reserved IP — Geolocation unavailable".
 * - For public IPs: queries public geolocation endpoint without requiring API keys.
 * - If lookup fails: returns "Geolocation unavailable" (never fabricates coordinates).
 */
export async function geolocateIp(ip: string): Promise<IpGeolocationData> {
  const cleanIp = (ip || '').trim().replace(/^\[|\]$/g, '');

  if (!cleanIp || cleanIp === 'Unavailable' || cleanIp === 'Internal Delivery') {
    return {
      status: 'UNAVAILABLE',
      ipType: 'UNAVAILABLE',
      displayLocation: 'Geolocation unavailable',
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      isp: null,
      asn: null,
      message: 'No IP address present in relay hop',
    };
  }

  // Check cache first
  if (geoCache.has(cleanIp)) {
    return geoCache.get(cleanIp)!;
  }

  // Check IP classification
  const classification = classifyIp(cleanIp);

  if (classification.isPrivateOrReserved) {
    const result: IpGeolocationData = {
      status: 'PRIVATE_RESERVED',
      ipType: classification.ipType,
      displayLocation: 'Private/Reserved IP — Geolocation unavailable',
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      isp: null,
      asn: null,
      message: classification.reason,
    };
    geoCache.set(cleanIp, result);
    return result;
  }

  // Public IP Geolocation
  // Attempt 1: ipwho.is (Free, HTTPS, no API key, reliable)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIp)}`, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'ThreatLens-Email-Forensics/1.0',
        Accept: 'application/json',
      },
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (data && data.success) {
        const parts: string[] = [];
        if (data.city) parts.push(data.city);
        if (data.region) parts.push(data.region);
        if (data.country) parts.push(data.country);

        const displayLocation = parts.length > 0
          ? `${parts.join(', ')} (Approximate)`
          : 'Approximate geolocation resolved';

        const result: IpGeolocationData = {
          status: 'SUCCESS',
          ipType: 'PUBLIC',
          displayLocation,
          country: data.country || null,
          region: data.region || null,
          city: data.city || null,
          latitude: typeof data.latitude === 'number' ? data.latitude : null,
          longitude: typeof data.longitude === 'number' ? data.longitude : null,
          isp: data.connection?.isp || null,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
          message: 'Approximate network location resolved via public geolocation registry',
        };

        geoCache.set(cleanIp, result);
        return result;
      }
    }
  } catch (err) {
    // Primary provider error, try fallback
  }

  // Attempt 2: freeipapi.com (Fallback, HTTPS, free, no key)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(cleanIp)}`, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'ThreatLens-Email-Forensics/1.0',
        Accept: 'application/json',
      },
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (data && data.countryName) {
        const parts: string[] = [];
        if (data.cityName) parts.push(data.cityName);
        if (data.regionName) parts.push(data.regionName);
        if (data.countryName) parts.push(data.countryName);

        const displayLocation = parts.length > 0
          ? `${parts.join(', ')} (Approximate)`
          : 'Approximate geolocation resolved';

        const result: IpGeolocationData = {
          status: 'SUCCESS',
          ipType: 'PUBLIC',
          displayLocation,
          country: data.countryName || null,
          region: data.regionName || null,
          city: data.cityName || null,
          latitude: typeof data.latitude === 'number' ? data.latitude : null,
          longitude: typeof data.longitude === 'number' ? data.longitude : null,
          isp: null,
          asn: null,
          message: 'Approximate network location resolved via secondary geolocation registry',
        };

        geoCache.set(cleanIp, result);
        return result;
      }
    }
  } catch (err) {
    // Both failed
  }

  // Fallback if all attempts fail
  const fallbackResult: IpGeolocationData = {
    status: 'UNAVAILABLE',
    ipType: 'PUBLIC',
    displayLocation: 'Geolocation unavailable',
    country: null,
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    isp: null,
    asn: null,
    message: 'Public geolocation service was unreachable or returned no record',
  };

  geoCache.set(cleanIp, fallbackResult);
  return fallbackResult;
}
