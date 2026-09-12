/**
 * ThreatLens Server-Side Domain Registration Age Intelligence Service
 *
 * Implements real WHOIS / RDAP domain registration lookups adhering to RFC 7480-7484 & RFC 9083.
 * Supports:
 * - Direct authoritative ICANN/IANA RDAP registries (Verisign, PIR, Nominet, Identity Digital, Google Registry, etc.)
 * - Optional WHOIS API integration via process.env.WHOIS_API_KEY (e.g., WhoisXML API)
 * - Strict risk engine scoring:
 *     - Recently registered (<30 days): +15 risk points, flag "Recently Registered Domain"
 *     - Older than 30 days: +0 risk points
 *     - Unavailable / timeout / rate-limited: +0 risk points ("Domain age unavailable")
 * - Never returns simulated responses or fake registration dates.
 */

export interface DomainAgeResult {
  domain: string;
  registrationDate: string | null;
  ageInDays: number | null;
  domainAge: string;
  isRecentlyRegistered: boolean;
  lookupStatus: 'RECENTLY_REGISTERED' | 'ESTABLISHED' | 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR';
  registrar: string | null;
  riskPoints: number;
  evidenceText: string;
  provider: 'RDAP' | 'WHOIS_API' | 'UNAVAILABLE';
}

// In-memory cache of IANA bootstrap services to reduce lookup latency
let ianaBootstrapCache: Array<[string[], string[]]> | null = null;
let lastBootstrapFetch = 0;
const BOOTSTRAP_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Well-known fallback RDAP registries for immediate lookup
const KNOWN_REGISTRIES: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/',
  net: 'https://rdap.verisign.com/net/v1/',
  org: 'https://rdap.publicinterestregistry.org/rdap/',
  ai: 'https://rdap.identitydigital.services/rdap/',
  io: 'https://rdap.nic.io/',
  dev: 'https://pubapi.registry.google/rdap/',
  app: 'https://pubapi.registry.google/rdap/',
  page: 'https://pubapi.registry.google/rdap/',
  uk: 'https://rdap.nominet.uk/uk/',
  co: 'https://rdap.nic.co/',
  us: 'https://rdap.nic.us/',
  biz: 'https://rdap.biz/',
  info: 'https://rdap.afilias.info/rdap/',
  me: 'https://rdap.nic.me/',
  ca: 'https://rdap.ca.fury.ca/rdap/',
  de: 'https://rdap.denic.de/',
  nl: 'https://rdap.sidn.nl/',
  fr: 'https://rdap.afnic.fr/',
};

/**
 * Extract clean sender domain from email or header string
 */
export function extractSenderDomain(senderInput: string): string {
  if (!senderInput || typeof senderInput !== 'string') return '';
  let cleaned = senderInput.trim();

  // Extract from RFC 822 format: "Name" <user@domain.com>
  const angleMatch = cleaned.match(/<([^>]+)>/);
  if (angleMatch) {
    cleaned = angleMatch[1];
  }

  // Extract after @
  const atIndex = cleaned.lastIndexOf('@');
  if (atIndex !== -1) {
    cleaned = cleaned.slice(atIndex + 1);
  }

  // Strip ports, protocols, queries, trailing dots
  cleaned = cleaned.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim().toLowerCase();
  cleaned = cleaned.replace(/^\.+|\.+$/g, '');

  return cleaned;
}

/**
 * Fetch authoritative RDAP server from IANA DNS bootstrap
 */
async function getAuthoritativeRdapUrl(domain: string): Promise<string | null> {
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1].toLowerCase();

  // 1. Check known fast registries
  if (KNOWN_REGISTRIES[tld]) {
    return KNOWN_REGISTRIES[tld];
  }

  // 2. Query IANA bootstrap
  try {
    const now = Date.now();
    if (!ianaBootstrapCache || now - lastBootstrapFetch > BOOTSTRAP_CACHE_TTL) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const resp = await fetch('https://data.iana.org/rdap/dns.json', {
        signal: controller.signal,
        headers: { 'User-Agent': 'ThreatLens-Security/1.0', Accept: 'application/json' },
      });
      clearTimeout(timeoutId);

      if (resp.ok) {
        const data = (await resp.json()) as { services: Array<[string[], string[]]> };
        if (Array.isArray(data.services)) {
          ianaBootstrapCache = data.services;
          lastBootstrapFetch = now;
        }
      }
    }

    if (ianaBootstrapCache) {
      const match = ianaBootstrapCache.find((service) =>
        service[0].some((ext) => ext.toLowerCase() === tld)
      );
      if (match && match[1] && match[1][0]) {
        return match[1][0];
      }
    }
  } catch (err) {
    // Network or timeout in bootstrap fetch - proceed with null
  }

  return null;
}

/**
 * Perform domain registration lookup using WhoisXML API if process.env.WHOIS_API_KEY is configured
 */
async function lookupViaWhoisApi(domain: string, apiKey: string): Promise<DomainAgeResult | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);

    const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${encodeURIComponent(
      apiKey
    )}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;

    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeoutId);

    if (resp.status === 429) {
      return null; // Rate limited, fall back to RDAP
    }

    if (!resp.ok) {
      return null;
    }

    const data = (await resp.json()) as any;
    const record = data?.WhoisRecord || data?.registryData;
    const createdDateStr = record?.createdDate || record?.registryData?.createdDate;
    const registrar = record?.registrarName || record?.registryData?.registrarName || null;

    if (createdDateStr) {
      return calculateDomainAgeResult(domain, createdDateStr, registrar, 'WHOIS_API');
    }
  } catch (err) {
    // Fall back to RDAP on error
  }
  return null;
}

/**
 * Perform domain registration lookup via official IETF RDAP (RFC 7480/9083)
 */
async function lookupViaRdap(domain: string): Promise<DomainAgeResult> {
  const authoritativeBase = await getAuthoritativeRdapUrl(domain);
  const targetUrls: string[] = [];

  if (authoritativeBase) {
    const base = authoritativeBase.endsWith('/') ? authoritativeBase : authoritativeBase + '/';
    targetUrls.push(`${base}domain/${domain}`);
  }
  // Secondary fallback via public rdap.org
  targetUrls.push(`https://rdap.org/domain/${domain}`);

  for (const url of targetUrls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);

      const resp = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'ThreatLens-Security-Agent/1.0',
          Accept: 'application/rdap+json, application/json',
        },
      });
      clearTimeout(timeoutId);

      if (resp.status === 404) {
        // Domain not found / not registered
        return createUnavailableResult(domain, 'UNAVAILABLE');
      }

      if (resp.status === 429) {
        // Rate limited
        continue;
      }

      if (resp.ok) {
        const rdapData = (await resp.json()) as any;

        // Extract creation / registration event
        let regDateStr: string | null = null;
        if (Array.isArray(rdapData.events)) {
          const regEvent = rdapData.events.find(
            (e: any) =>
              e.eventAction === 'registration' ||
              e.eventAction === 'created' ||
              e.eventAction === 'transfer'
          );
          if (regEvent && regEvent.eventDate) {
            regDateStr = regEvent.eventDate;
          }
        }

        // Extract Registrar name from entities
        let registrarName: string | null = null;
        if (Array.isArray(rdapData.entities)) {
          const registrarEntity = rdapData.entities.find((ent: any) =>
            Array.isArray(ent.roles) && ent.roles.includes('registrar')
          );
          if (registrarEntity) {
            if (Array.isArray(registrarEntity.vcardArray?.[1])) {
              const fnEntry = registrarEntity.vcardArray[1].find((prop: any) => prop?.[0] === 'fn');
              if (fnEntry && fnEntry[3]) {
                registrarName = String(fnEntry[3]);
              }
            }
            if (!registrarName && registrarEntity.handle) {
              registrarName = String(registrarEntity.handle);
            }
          }
        }

        if (regDateStr) {
          return calculateDomainAgeResult(domain, regDateStr, registrarName, 'RDAP');
        }
      }
    } catch (err: any) {
      // Abort or network failure, try next URL
    }
  }

  return createUnavailableResult(domain, 'UNAVAILABLE');
}

/**
 * Calculate domain age and apply exact risk point logic
 */
function calculateDomainAgeResult(
  domain: string,
  registrationDateStr: string,
  registrar: string | null,
  provider: 'RDAP' | 'WHOIS_API'
): DomainAgeResult {
  const regDate = new Date(registrationDateStr);
  if (isNaN(regDate.getTime())) {
    return createUnavailableResult(domain, 'UNAVAILABLE');
  }

  // Calculate age against current time
  const now = new Date();
  const diffMs = now.getTime() - regDate.getTime();
  const ageInDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

  const isRecentlyRegistered = ageInDays < 30;

  let domainAgeFormatted: string;
  let riskPoints = 0;
  let lookupStatus: DomainAgeResult['lookupStatus'];
  let evidenceText: string;

  if (isRecentlyRegistered) {
    lookupStatus = 'RECENTLY_REGISTERED';
    domainAgeFormatted = `Registered ${ageInDays} day${ageInDays === 1 ? '' : 's'} ago`;
    riskPoints = 15;
    evidenceText = `Recently registered domain (${domainAgeFormatted}) [+15 risk points]`;
  } else {
    lookupStatus = 'ESTABLISHED';
    riskPoints = 0;
    if (ageInDays < 365) {
      const months = Math.floor(ageInDays / 30);
      domainAgeFormatted = `${months} month${months === 1 ? '' : 's'} (${ageInDays} days)`;
    } else {
      const years = (ageInDays / 365.25).toFixed(1);
      domainAgeFormatted = `${years} years (${ageInDays.toLocaleString()} days)`;
    }
    evidenceText = `Sender domain age established: ${domainAgeFormatted} (+0 risk points)`;
  }

  return {
    domain,
    registrationDate: regDate.toISOString(),
    ageInDays,
    domainAge: domainAgeFormatted,
    isRecentlyRegistered,
    lookupStatus,
    registrar,
    riskPoints,
    evidenceText,
    provider,
  };
}

/**
 * Handle unavailable domain registration data gracefully
 * Strictly adheres to rule:
 * - Does NOT invent a registration date
 * - Does NOT assume the domain is newly registered
 * - Does NOT increase risk score (adds +0 points)
 */
function createUnavailableResult(
  domain: string,
  status: 'UNAVAILABLE' | 'RATE_LIMITED' | 'ERROR' = 'UNAVAILABLE'
): DomainAgeResult {
  return {
    domain,
    registrationDate: null,
    ageInDays: null,
    domainAge: 'Domain age unavailable',
    isRecentlyRegistered: false,
    lookupStatus: status,
    registrar: null,
    riskPoints: 0,
    evidenceText: 'Domain age unavailable (+0 risk points)',
    provider: 'UNAVAILABLE',
  };
}

/**
 * Main public entry point: queries real domain registration age intelligence
 */
export async function lookupDomainRegistrationAge(rawSenderOrDomain: string): Promise<DomainAgeResult> {
  const domain = extractSenderDomain(rawSenderOrDomain);

  // Validate domain format
  if (!domain || !domain.includes('.') || domain.length > 253) {
    return createUnavailableResult(rawSenderOrDomain || 'unknown', 'UNAVAILABLE');
  }

  // Reject local IP addresses or invalid TLD syntax
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain) || domain.endsWith('.local') || domain.endsWith('.internal')) {
    return createUnavailableResult(domain, 'UNAVAILABLE');
  }

  // 1. Check if WHOIS_API_KEY is configured
  const whoisApiKey = process.env.WHOIS_API_KEY;
  if (whoisApiKey && whoisApiKey !== 'MY_WHOIS_API_KEY' && whoisApiKey.trim().length > 0) {
    const apiResult = await lookupViaWhoisApi(domain, whoisApiKey);
    if (apiResult) {
      return apiResult;
    }
  }

  // 2. Perform live RDAP lookup
  return await lookupViaRdap(domain);
}
