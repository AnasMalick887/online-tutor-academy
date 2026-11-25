import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { UserRole, AccountStatus, SRS_CONSTANTS } from '../src/shared/srsConstants.ts';

const EPHEMERAL_SECRET = crypto.randomBytes(32).toString('hex');

function getSigningSecret(): string {
  return process.env.SESSION_SECRET?.trim() || EPHEMERAL_SECRET;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, originalHex] = parts;
  if (!salt || !originalHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const original = Buffer.from(originalHex, 'hex');
  if (derived.length !== original.length) return false;
  return crypto.timingSafeEqual(derived, original);
}

export function validatePasswordStrength(password: string): string | null {
  if (typeof password !== 'string' || password.length < SRS_CONSTANTS.MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${SRS_CONSTANTS.MIN_PASSWORD_LENGTH} characters long.`;
  }
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must contain at least one letter and one digit.';
  }
  return null;
}

export function sanitizeSafeUrl(rawUrl: string | undefined | null): string | null {
  if (!rawUrl || !rawUrl.trim()) return null;
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

export interface SessionRecord {
  tokenId: string;
  userId: string;
  role: UserRole;
  impersonatedBy?: string;
  lastActivityAt: number;
}

// In-memory active session registry enforcing SESSION_TIMEOUT_MIN (30 min inactivity)
const activeSessions = new Map<string, SessionRecord>();

export function createSessionToken(userId: string, role: UserRole, impersonatedBy?: string): string {
  const tokenId = crypto.randomBytes(24).toString('hex');
  const payload = Buffer.from(
    JSON.stringify({
      tid: tokenId,
      uid: userId,
      role,
      imp: impersonatedBy || null,
      iat: Date.now(),
    })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', getSigningSecret()).update(payload).digest('base64url');

  activeSessions.set(tokenId, {
    tokenId,
    userId,
    role,
    impersonatedBy,
    lastActivityAt: Date.now(),
  });

  return `${payload}.${sig}`;
}

export function verifySessionToken(token: string): SessionRecord | null {
  if (!token || typeof token !== 'string') return null;
  const dotIdx = token.indexOf('.');
  if (dotIdx <= 0) return null;
  const payload = token.slice(0, dotIdx);
  const sig = token.slice(dotIdx + 1);
  if (!payload || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', getSigningSecret())
    .update(payload)
    .digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      tid: string;
      uid: string;
      role: UserRole;
      imp?: string | null;
    };
    const record = activeSessions.get(parsed.tid);
    if (!record) return null;

    const timeoutMs = SRS_CONSTANTS.SESSION_TIMEOUT_MIN * 60 * 1000;
    if (Date.now() - record.lastActivityAt > timeoutMs) {
      activeSessions.delete(parsed.tid);
      return null;
    }

    record.lastActivityAt = Date.now();
    return record;
  } catch {
    return null;
  }
}

export function revokeSessionToken(token: string): void {
  const dotIdx = token.indexOf('.');
  if (dotIdx <= 0) return;
  try {
    const payload = token.slice(0, dotIdx);
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { tid?: string };
    if (parsed.tid) {
      activeSessions.delete(parsed.tid);
    }
  } catch {
    // ignore malformed token
  }
}

export function revokeAllUserSessions(userId: string): void {
  for (const [tid, session] of activeSessions.entries()) {
    if (session.userId === userId) {
      activeSessions.delete(tid);
    }
  }
}

export interface AuthenticatedRequest extends Request {
  auth?: SessionRecord & { status: AccountStatus; email: string; fullName: string };
}

export function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice(7).trim();
}

export function createRequireAuth(getUserById: (id: string) => { id: string; status: string; email: string; full_name: string; deleted_at: string | null } | undefined) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const token = extractBearerToken(req);
    if (!token) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    const session = verifySessionToken(token);
    if (!session) {
      res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
      return;
    }
    const user = getUserById(session.userId);
    if (!user || user.deleted_at || user.status === AccountStatus.Suspended || user.status === AccountStatus.Deleted) {
      revokeSessionToken(token);
      res.status(403).json({ error: 'Account is suspended or unavailable.' });
      return;
    }
    req.auth = {
      ...session,
      status: user.status as AccountStatus,
      email: user.email,
      fullName: user.full_name,
    };
    next();
  };
}

export function requireRole(...roles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.auth) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!roles.includes(req.auth.role)) {
      res.status(403).json({ error: 'You do not have permission to access this resource.' });
      return;
    }
    next();
  };
}

const ABUSIVE_WORDS = ['scam', 'idiot', 'stupid', 'fraud', 'hate', 'trash', 'loser'];

export function containsAbusiveLanguage(text: string): boolean {
  const lower = text.toLowerCase();
  return ABUSIVE_WORDS.some((w) => new RegExp(`\\b${w}\\b`, 'i').test(lower));
}
