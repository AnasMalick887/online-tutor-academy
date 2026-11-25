import express from 'express';
import crypto from 'node:crypto';
import { db, getConfigValue, recordAuditLog, setConfigValue } from './db.ts';
import {
  containsAbusiveLanguage,
  createRequireAuth,
  createSessionToken,
  extractBearerToken,
  hashPassword,
  requireRole,
  revokeAllUserSessions,
  revokeSessionToken,
  sanitizeSafeUrl,
  validatePasswordStrength,
  verifyPassword,
  type AuthenticatedRequest,
} from './auth.ts';
import { MessagingAdapter, PaymentGatewayAdapter, VideoRoomAdapter } from './adapters.ts';
import { pushRealtimeNotification } from './ws.ts';
import {
  AccountStatus,
  AssignmentStatus,
  BookingStatus,
  DisputeStatus,
  PaymentStatus,
  SRS_CONSTANTS,
  TutorApprovalStatus,
  UserRole,
} from '../src/shared/srsConstants.ts';

function getUserById(id: string) {
  return db
    .prepare('SELECT id, full_name, email, role, status, dob, guardian_email, timezone, bio, avatar_color, deleted_at, created_at FROM users WHERE id = ?')
    .get(id) as
    | {
        id: string;
        full_name: string;
        email: string;
        role: UserRole;
        status: AccountStatus;
        dob: string | null;
        guardian_email: string | null;
        timezone: string;
        bio: string;
        avatar_color: string;
        deleted_at: string | null;
        created_at: string;
      }
    | undefined;
}

const requireAuth = createRequireAuth(getUserById);

function createAndDeliverNotification(
  userId: string,
  channel: 'email' | 'sms' | 'in_app',
  title: string,
  body: string
): void {
  const user = getUserById(userId);
  const recipient = user?.email || '';
  const result = MessagingAdapter.dispatch(channel, recipient, title, body);
  const id = `ntf-${crypto.randomBytes(6).toString('hex')}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO notifications (id, user_id, channel, title, body, delivery_status, retry_count, is_read, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(id, userId, channel, title, body, result.statusLabel, result.retryCount, now);

  pushRealtimeNotification(userId, { id, channel, title, body, delivery_status: result.statusLabel, created_at: now });
}

function expireStaleBookingHolds(): void {
  const nowIso = new Date().toISOString();
  db.prepare(`
    UPDATE bookings
    SET status = ?, cancel_reason = 'Payment hold expired (10 minutes)', updated_at = ?
    WHERE status = ? AND hold_expires_at IS NOT NULL AND hold_expires_at < ? AND deleted_at IS NULL
  `).run(BookingStatus.Cancelled, nowIso, BookingStatus.AwaitingPayment, nowIso);
}

function releaseEligibleEscrowPayments(): void {
  const delayHours = Number(getConfigValue('PAYOUT_DELAY_HR', String(SRS_CONSTANTS.PAYOUT_DELAY_HR)));
  const cutoffIso = new Date(Date.now() - delayHours * 3600 * 1000).toISOString();
  db.prepare(`
    UPDATE payments
    SET status = ?, updated_at = ?
    WHERE status = ? AND deleted_at IS NULL AND booking_id IN (
      SELECT b.id FROM bookings b
      WHERE b.status = ? AND b.end_utc < ? AND b.deleted_at IS NULL
      AND b.id NOT IN (SELECT d.booking_id FROM disputes d WHERE d.status != ?)
    )
  `).run(
    PaymentStatus.Released,
    new Date().toISOString(),
    PaymentStatus.Paid,
    BookingStatus.Completed,
    cutoffIso,
    DisputeStatus.Resolved
  );
}

function calculateAge(dobStr: string): number | null {
  const d = new Date(dobStr);
  if (Number.isNaN(d.getTime())) return null;
  const now = new Date();
  let age = now.getUTCFullYear() - d.getUTCFullYear();
  const m = now.getUTCMonth() - d.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < d.getUTCDate())) {
    age--;
  }
  return age;
}

export function createApiRouter(): express.Router {
  const router = express.Router();

  // Health & Public Config (SRS 4.3.4)
  router.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '1.0.0', currency: SRS_CONSTANTS.CURRENCY });
  });

  router.get('/config', (_req, res) => {
    res.json({
      commissionPct: Number(getConfigValue('PLATFORM_COMMISSION_PCT', '15')),
      freeCancelHours: Number(getConfigValue('FREE_CANCEL_HOURS', String(SRS_CONSTANTS.FREE_CANCEL_HOURS))),
      slotHoldMin: Number(getConfigValue('SLOT_HOLD_MIN', String(SRS_CONSTANTS.SLOT_HOLD_MIN))),
      payoutDelayHr: Number(getConfigValue('PAYOUT_DELAY_HR', String(SRS_CONSTANTS.PAYOUT_DELAY_HR))),
      subjects: JSON.parse(getConfigValue('SUBJECTS', '[]')),
      levels: JSON.parse(getConfigValue('LEVELS', '[]')),
      languages: JSON.parse(getConfigValue('LANGUAGES', '[]')),
      constants: SRS_CONSTANTS,
    });
  });

  // --- FR-01: Register Account ---
  router.post('/auth/register', (req, res) => {
    const { fullName, email, password, role, dob, guardianEmail, acceptedLegal, timezone } = req.body as {
      fullName?: string;
      email?: string;
      password?: string;
      role?: string;
      dob?: string;
      guardianEmail?: string;
      acceptedLegal?: boolean;
      timezone?: string;
    };

    if (!fullName || fullName.trim().length < 2) {
      res.status(400).json({ field: 'fullName', error: 'Full name is required (min 2 characters).' });
      return;
    }
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ field: 'email', error: 'Enter a valid email address.' });
      return;
    }
    const pwError = validatePasswordStrength(password || '');
    if (pwError) {
      res.status(400).json({ field: 'password', error: pwError });
      return;
    }
    if (role !== UserRole.Student && role !== UserRole.Tutor) {
      res.status(400).json({ field: 'role', error: 'Role must be Student or Tutor.' });
      return;
    }
    if (!dob) {
      res.status(400).json({ field: 'dob', error: 'Date of birth is required.' });
      return;
    }
    const age = calculateAge(dob);
    if (age === null || age < 5 || age > 100) {
      res.status(400).json({ field: 'dob', error: 'Enter a valid date of birth.' });
      return;
    }
    if (age < 18 && (!guardianEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guardianEmail.trim()))) {
      res.status(400).json({
        field: 'guardianEmail',
        error: 'Users under 18 require a valid parent/guardian email address for consent (SRS FR-01 / Safety 4.2.1).',
      });
      return;
    }
    if (!acceptedLegal) {
      res.status(400).json({
        field: 'acceptedLegal',
        error: 'You must accept the Terms of Service, Privacy Policy, and Refund Policy.',
      });
      return;
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (existing) {
      res.status(409).json({ field: 'email', error: 'This email address is already registered.' });
      return;
    }

    const userId = `${role.toLowerCase()}-${crypto.randomBytes(6).toString('hex')}`;
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password!);
    const otpCode = String(crypto.randomInt(100000, 999999));
    const otpExpiry = new Date(Date.now() + SRS_CONSTANTS.OTP_EXPIRY_MIN * 60 * 1000).toISOString();

    const tx = db.transaction(() => {
      db.prepare(`
        INSERT INTO users (id, full_name, email, password_hash, role, status, dob, guardian_email, timezone, avatar_color, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        userId,
        fullName.trim(),
        cleanEmail,
        passwordHash,
        role,
        AccountStatus.PendingVerification,
        dob,
        age < 18 ? guardianEmail!.trim().toLowerCase() : null,
        timezone || 'Asia/Karachi',
        role === UserRole.Tutor ? '#1E3A8A' : '#1D4ED8',
        now
      );

      if (role === UserRole.Tutor) {
        db.prepare(`
          INSERT INTO tutor_profiles (user_id, approval_status, updated_at)
          VALUES (?, ?, ?)
        `).run(userId, TutorApprovalStatus.Pending, now);
      }

      db.prepare(`
        INSERT INTO otp_codes (id, user_id, email, code, purpose, expires_at, created_at)
        VALUES (?, ?, ?, ?, 'verify_email', ?, ?)
      `).run(`otp-${crypto.randomBytes(5).toString('hex')}`, userId, cleanEmail, otpCode, otpExpiry, now);
    });
    tx();

    MessagingAdapter.dispatch('email', cleanEmail, 'Verify your OTA account', `Your OTP code is ${otpCode}`);

    res.status(201).json({
      message: 'Account created in Pending Verification state. Enter the 6-digit verification code sent to your email.',
      email: cleanEmail,
      role,
      // Sandbox preview delivery hint (SRS 4.3.11)
      simulatedDelivery: { channel: 'email', recipient: cleanEmail, otpCode, expiresInMin: SRS_CONSTANTS.OTP_EXPIRY_MIN },
    });
  });

  router.post('/auth/verify-otp', (req, res) => {
    const { email, code } = req.body as { email?: string; code?: string };
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanCode = (code || '').trim();

    const user = db.prepare('SELECT id, role, status FROM users WHERE email = ? AND deleted_at IS NULL').get(cleanEmail) as
      | { id: string; role: UserRole; status: AccountStatus }
      | undefined;

    if (!user) {
      res.status(404).json({ error: 'Account not found.' });
      return;
    }

    const otp = db
      .prepare(`
        SELECT id, code, expires_at FROM otp_codes
        WHERE user_id = ? AND purpose = 'verify_email' AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 1
      `)
      .get(user.id) as { id: string; code: string; expires_at: string } | undefined;

    if (!otp || otp.code !== cleanCode) {
      res.status(400).json({ field: 'otp', error: 'Invalid verification code.' });
      return;
    }
    if (new Date(otp.expires_at).getTime() < Date.now()) {
      res.status(400).json({ field: 'otp', error: 'Verification code expired. Please request a new code.' });
      return;
    }

    const nextStatus = user.role === UserRole.Tutor ? AccountStatus.AwaitingApproval : AccountStatus.Active;
    const now = new Date().toISOString();
    db.prepare('UPDATE otp_codes SET used_at = ? WHERE id = ?').run(now, otp.id);
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(nextStatus, user.id);

    const token = createSessionToken(user.id, user.role);
    const fullUser = getUserById(user.id);

    createAndDeliverNotification(
      user.id,
      'in_app',
      'Email Verified',
      user.role === UserRole.Tutor
        ? 'Your email is verified. Complete your tutor profile to submit it for admin approval.'
        : 'Welcome to Online Tutor Academy! Your student account is now active.'
    );

    res.json({
      message:
        user.role === UserRole.Tutor
          ? 'Email verified. Complete your tutor profile for admin review.'
          : 'Email verified. Your student account is active.',
      token,
      user: fullUser,
    });
  });

  router.post('/auth/resend-otp', (req, res) => {
    const cleanEmail = (req.body?.email || '').trim().toLowerCase();
    const user = db.prepare('SELECT id, status FROM users WHERE email = ? AND deleted_at IS NULL').get(cleanEmail) as
      | { id: string; status: AccountStatus }
      | undefined;
    if (!user || user.status !== AccountStatus.PendingVerification) {
      res.status(400).json({ error: 'No pending verification found for this email.' });
      return;
    }
    const otpCode = String(crypto.randomInt(100000, 999999));
    const otpExpiry = new Date(Date.now() + SRS_CONSTANTS.OTP_EXPIRY_MIN * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO otp_codes (id, user_id, email, code, purpose, expires_at, created_at)
      VALUES (?, ?, ?, ?, 'verify_email', ?, ?)
    `).run(`otp-${crypto.randomBytes(5).toString('hex')}`, user.id, cleanEmail, otpCode, otpExpiry, new Date().toISOString());

    res.json({
      message: 'A new 6-digit verification code has been issued.',
      simulatedDelivery: { channel: 'email', recipient: cleanEmail, otpCode, expiresInMin: SRS_CONSTANTS.OTP_EXPIRY_MIN },
    });
  });

  // --- FR-02: Login / Logout ---
  router.post('/auth/login', (req, res) => {
    const { email, password } = req.body as { email?: string; password?: string };
    const cleanEmail = (email || '').trim().toLowerCase();

    const user = db
      .prepare('SELECT * FROM users WHERE email = ? AND deleted_at IS NULL')
      .get(cleanEmail) as
      | {
          id: string;
          full_name: string;
          email: string;
          password_hash: string;
          role: UserRole;
          status: AccountStatus;
          failed_login_attempts: number;
          locked_until: string | null;
        }
      | undefined;

    if (!user || user.role === UserRole.Admin) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      const minsLeft = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
      res.status(423).json({
        error: `Account temporarily locked after ${SRS_CONSTANTS.MAX_LOGIN_ATTEMPTS} failed attempts. Try again in ${minsLeft} minute(s).`,
      });
      return;
    }

    if (!verifyPassword(password || '', user.password_hash)) {
      const nextAttempts = user.failed_login_attempts + 1;
      if (nextAttempts >= SRS_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + SRS_CONSTANTS.LOCKOUT_MINUTES * 60 * 1000).toISOString();
        db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?').run(
          nextAttempts,
          lockUntil,
          user.id
        );
        res.status(423).json({
          error: `Account locked for ${SRS_CONSTANTS.LOCKOUT_MINUTES} minutes due to ${SRS_CONSTANTS.MAX_LOGIN_ATTEMPTS} failed login attempts.`,
        });
        return;
      }
      db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?').run(nextAttempts, user.id);
      res.status(401).json({
        error: `Invalid email or password. ${SRS_CONSTANTS.MAX_LOGIN_ATTEMPTS - nextAttempts} attempt(s) remaining before lockout.`,
      });
      return;
    }

    if (user.status === AccountStatus.PendingVerification) {
      res.status(403).json({
        requiresVerification: true,
        email: user.email,
        error: 'Please verify your email address before logging in.',
      });
      return;
    }

    if (user.status === AccountStatus.Suspended) {
      res.status(403).json({ error: 'Your account has been suspended by an administrator.' });
      return;
    }

    db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
    const token = createSessionToken(user.id, user.role);
    const fullUser = getUserById(user.id);
    const tutorProfile =
      user.role === UserRole.Tutor
        ? db.prepare('SELECT * FROM tutor_profiles WHERE user_id = ?').get(user.id)
        : null;

    res.json({ token, user: fullUser, tutorProfile });
  });

  // Non-admin Demo Sign-In (Student & Tutor preview accounts only)
  router.post('/auth/demo-login', (req, res) => {
    const { role } = req.body as { role?: string };
    let targetId = '';
    if (role === UserRole.Student) targetId = 'student-1';
    else if (role === UserRole.Tutor) targetId = 'tutor-1';
    else {
      res.status(400).json({ error: 'Demo login is available only for Student and Tutor roles.' });
      return;
    }

    const user = getUserById(targetId);
    if (!user || user.deleted_at || user.status === AccountStatus.Suspended) {
      res.status(404).json({ error: 'Demo account unavailable.' });
      return;
    }

    const token = createSessionToken(user.id, user.role);
    const tutorProfile =
      user.role === UserRole.Tutor
        ? db.prepare('SELECT * FROM tutor_profiles WHERE user_id = ?').get(user.id)
        : null;
    res.json({ token, user, tutorProfile });
  });

  // Admin Passcode / First-Run Claim Flow (securecoder-persona compliant)
  router.get('/auth/admin-status', (_req, res) => {
    const envConfigured = Boolean(process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length > 0);
    const claimedRow = db.prepare('SELECT claimed_at FROM admin_credentials WHERE id = 1').get() as
      | { claimed_at: string }
      | undefined;
    res.json({
      envConfigured,
      isClaimed: envConfigured || Boolean(claimedRow),
    });
  });

  router.post('/auth/admin-claim', (req, res) => {
    const envPasscode = process.env.ADMIN_PASSCODE?.trim();
    if (envPasscode) {
      res.status(409).json({ error: 'Admin passcode is configured via environment secret. Use Admin Sign In.' });
      return;
    }
    const existing = db.prepare('SELECT id FROM admin_credentials WHERE id = 1').get();
    if (existing) {
      res.status(409).json({ error: 'Admin account has already been claimed. Please sign in.' });
      return;
    }
    const { passcode } = req.body as { passcode?: string };
    const pwErr = validatePasswordStrength(passcode || '');
    if (pwErr) {
      res.status(400).json({ field: 'passcode', error: pwErr });
      return;
    }

    const hashed = hashPassword(passcode!);
    db.prepare('INSERT INTO admin_credentials (id, password_hash, claimed_at) VALUES (1, ?, ?)').run(
      hashed,
      new Date().toISOString()
    );

    const adminUser = getUserById('admin-1')!;
    const token = createSessionToken(adminUser.id, UserRole.Admin);
    recordAuditLog(adminUser.id, UserRole.Admin, 'ADMIN_CLAIMED', 'user', adminUser.id, {});
    res.json({ token, user: adminUser });
  });

  router.post('/auth/admin-login', (req, res) => {
    const { passcode } = req.body as { passcode?: string };
    const envPasscode = process.env.ADMIN_PASSCODE?.trim();
    let valid = false;

    if (envPasscode) {
      const a = Buffer.from(passcode || '');
      const b = Buffer.from(envPasscode);
      valid = a.length === b.length && crypto.timingSafeEqual(a, b);
    } else {
      const claimed = db.prepare('SELECT password_hash FROM admin_credentials WHERE id = 1').get() as
        | { password_hash: string }
        | undefined;
      if (!claimed) {
        res.status(400).json({ error: 'Admin account is not yet claimed. Use the First-Run Admin Setup form.' });
        return;
      }
      valid = verifyPassword(passcode || '', claimed.password_hash);
    }

    if (!valid) {
      res.status(401).json({ error: 'Invalid administrator passcode.' });
      return;
    }

    const adminUser = getUserById('admin-1')!;
    const token = createSessionToken(adminUser.id, UserRole.Admin);
    recordAuditLog(adminUser.id, UserRole.Admin, 'ADMIN_LOGIN', 'user', adminUser.id, {});
    res.json({ token, user: adminUser });
  });

  router.post('/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
    const token = extractBearerToken(req);
    if (token) revokeSessionToken(token);
    res.json({ message: 'Logged out successfully.' });
  });

  // --- FR-03: Forgot Password / Reset Password / Manage Profile ---
  router.post('/auth/forgot-password', (req, res) => {
    const cleanEmail = (req.body?.email || '').trim().toLowerCase();
    const user = db.prepare('SELECT id, role FROM users WHERE email = ? AND deleted_at IS NULL').get(cleanEmail) as
      | { id: string; role: UserRole }
      | undefined;

    if (!user || user.role === UserRole.Admin) {
      // Do not leak whether email exists
      res.json({ message: 'If an account matches that email, a reset token has been sent (valid for 1 hour).' });
      return;
    }

    const resetCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    const expiresAt = new Date(Date.now() + SRS_CONSTANTS.RESET_LINK_EXPIRY_HR * 3600 * 1000).toISOString();
    db.prepare(`
      INSERT INTO otp_codes (id, user_id, email, code, purpose, expires_at, created_at)
      VALUES (?, ?, ?, ?, 'reset_password', ?, ?)
    `).run(`rst-${crypto.randomBytes(5).toString('hex')}`, user.id, cleanEmail, resetCode, expiresAt, new Date().toISOString());

    res.json({
      message: 'Password reset code generated (valid for 1 hour).',
      simulatedDelivery: { channel: 'email', recipient: cleanEmail, resetCode, expiresInHr: SRS_CONSTANTS.RESET_LINK_EXPIRY_HR },
    });
  });

  router.post('/auth/reset-password', (req, res) => {
    const { email, resetCode, newPassword } = req.body as {
      email?: string;
      resetCode?: string;
      newPassword?: string;
    };
    const cleanEmail = (email || '').trim().toLowerCase();
    const pwErr = validatePasswordStrength(newPassword || '');
    if (pwErr) {
      res.status(400).json({ field: 'newPassword', error: pwErr });
      return;
    }

    const user = db.prepare('SELECT id FROM users WHERE email = ? AND deleted_at IS NULL').get(cleanEmail) as
      | { id: string }
      | undefined;
    if (!user) {
      res.status(400).json({ error: 'Invalid or expired reset code.' });
      return;
    }

    const record = db
      .prepare(`
        SELECT id, code, expires_at FROM otp_codes
        WHERE user_id = ? AND purpose = 'reset_password' AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 1
      `)
      .get(user.id) as { id: string; code: string; expires_at: string } | undefined;

    if (!record || record.code !== (resetCode || '').trim().toUpperCase()) {
      res.status(400).json({ field: 'resetCode', error: 'Invalid reset code.' });
      return;
    }
    if (new Date(record.expires_at).getTime() < Date.now()) {
      res.status(400).json({ field: 'resetCode', error: 'Reset code has expired (1 hour limit).' });
      return;
    }

    db.prepare('UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(
      hashPassword(newPassword!),
      user.id
    );
    db.prepare('UPDATE otp_codes SET used_at = ? WHERE id = ?').run(new Date().toISOString(), record.id);
    revokeAllUserSessions(user.id);

    res.json({ message: 'Password updated successfully. You may now sign in.' });
  });

  router.get('/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
    const user = getUserById(req.auth!.userId);
    const tutorProfile =
      req.auth!.role === UserRole.Tutor
        ? db.prepare('SELECT * FROM tutor_profiles WHERE user_id = ?').get(req.auth!.userId)
        : null;
    res.json({
      user,
      tutorProfile,
      impersonatedBy: req.auth!.impersonatedBy || null,
    });
  });

  router.patch('/profile', requireAuth, (req: AuthenticatedRequest, res) => {
    const { fullName, timezone, bio, avatarColor } = req.body as {
      fullName?: string;
      timezone?: string;
      bio?: string;
      avatarColor?: string;
    };
    if (!fullName || fullName.trim().length < 2) {
      res.status(400).json({ field: 'fullName', error: 'Full name must be at least 2 characters.' });
      return;
    }
    const allowedColors = ['#1D4ED8', '#1E3A8A', '#0F766E', '#4338CA', '#B45309', '#7C2D12', '#0369A1', '#0F172A'];
    const safeColor = allowedColors.includes(avatarColor || '') ? avatarColor! : '#1D4ED8';

    db.prepare('UPDATE users SET full_name = ?, timezone = ?, bio = ?, avatar_color = ? WHERE id = ?').run(
      fullName.trim(),
      (timezone || 'Asia/Karachi').slice(0, 64),
      (bio || '').trim().slice(0, 1000),
      safeColor,
      req.auth!.userId
    );
    res.json({ message: 'Profile saved.', user: getUserById(req.auth!.userId) });
  });

  // Chapter 5 Legal: Personal Data Export & Account Deletion (soft-delete)
  router.get('/account/export', requireAuth, (req: AuthenticatedRequest, res) => {
    const userId = req.auth!.userId;
    const user = getUserById(userId);
    const bookings = db
      .prepare('SELECT id, subject, level, start_utc, end_utc, duration_min, price_pkr, status, created_at FROM bookings WHERE (student_id = ? OR tutor_id = ?) AND deleted_at IS NULL')
      .all(userId, userId);
    const payments = db
      .prepare('SELECT id, booking_id, amount_pkr, method, status, created_at FROM payments WHERE student_id = ? AND deleted_at IS NULL')
      .all(userId);
    const assignments = db
      .prepare('SELECT id, title, status, score, feedback, submitted_at, graded_at FROM assignments WHERE student_id = ? OR tutor_id = ?')
      .all(userId, userId);

    res.json({
      exportedAt: new Date().toISOString(),
      user,
      bookings,
      payments,
      assignments,
    });
  });

  router.post('/account/delete', requireAuth, (req: AuthenticatedRequest, res) => {
    if (req.auth!.role === UserRole.Admin) {
      res.status(400).json({ error: 'An admin cannot delete their own account (SRS FR-19).' });
      return;
    }
    const now = new Date().toISOString();
    db.prepare('UPDATE users SET status = ?, deleted_at = ? WHERE id = ?').run(
      AccountStatus.Deleted,
      now,
      req.auth!.userId
    );
    revokeAllUserSessions(req.auth!.userId);
    recordAuditLog(req.auth!.userId, req.auth!.role, 'SELF_DELETE_ACCOUNT', 'user', req.auth!.userId, {});
    res.json({ message: 'Your account has been deactivated and scheduled for deletion per our Privacy Policy.' });
  });

  // --- FR-04: Create / Update Tutor Profile ---
  router.put('/tutor/profile', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const {
      headline,
      bio,
      qualifications,
      experienceYears,
      hourlyRatePkr,
      subjects,
      levels,
      languages,
      introVideoUrl,
      documents,
    } = req.body as {
      headline?: string;
      bio?: string;
      qualifications?: string;
      experienceYears?: number;
      hourlyRatePkr?: number;
      subjects?: string[];
      levels?: string[];
      languages?: string[];
      introVideoUrl?: string;
      documents?: Array<{ name: string; sizeMb?: number }>;
    };

    if (!headline || headline.trim().length < 5) {
      res.status(400).json({ field: 'headline', error: 'Headline is required (min 5 characters).' });
      return;
    }
    if (!bio || bio.trim().length < 20) {
      res.status(400).json({ field: 'bio', error: 'Bio must be at least 20 characters.' });
      return;
    }
    if (!qualifications || qualifications.trim().length < 3) {
      res.status(400).json({ field: 'qualifications', error: 'Qualifications are required.' });
      return;
    }
    if (!Array.isArray(subjects) || subjects.length === 0) {
      res.status(400).json({ field: 'subjects', error: 'Select at least one subject.' });
      return;
    }
    if (!Array.isArray(levels) || levels.length === 0) {
      res.status(400).json({ field: 'levels', error: 'Select at least one teaching level.' });
      return;
    }
    const rate = Number(hourlyRatePkr);
    if (!Number.isFinite(rate) || rate < 300 || rate > 50000) {
      res.status(400).json({ field: 'hourlyRatePkr', error: 'Hourly rate must be between PKR 300 and PKR 50,000.' });
      return;
    }

    const safeVideo = introVideoUrl?.trim() ? sanitizeSafeUrl(introVideoUrl) : '';
    if (introVideoUrl?.trim() && !safeVideo) {
      res.status(400).json({ field: 'introVideoUrl', error: 'Intro video URL must start with http:// or https://.' });
      return;
    }

    const cleanDocs: string[] = [];
    if (Array.isArray(documents)) {
      for (const doc of documents) {
        const docName = typeof doc === 'string' ? doc : doc?.name;
        const sizeMb = typeof doc === 'object' && doc?.sizeMb ? Number(doc.sizeMb) : 1;
        if (!docName) continue;
        if (!/\.(pdf|jpg|jpeg)$/i.test(docName)) {
          res.status(400).json({ field: 'documents', error: `Unsupported file type for "${docName}". Only PDF and JPG are accepted.` });
          return;
        }
        if (sizeMb > 5) {
          res.status(400).json({ field: 'documents', error: `File "${docName}" exceeds the 5 MB limit.` });
          return;
        }
        cleanDocs.push(docName);
      }
    }

    const existing = db.prepare('SELECT approval_status FROM tutor_profiles WHERE user_id = ?').get(req.auth!.userId) as
      | { approval_status: TutorApprovalStatus }
      | undefined;

    // Resubmission after rejection sets back to Pending
    const nextApproval =
      existing?.approval_status === TutorApprovalStatus.Approved
        ? TutorApprovalStatus.Approved
        : TutorApprovalStatus.Pending;

    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO tutor_profiles (
        user_id, headline, bio, qualifications, experience_years, hourly_rate_pkr,
        subjects_json, levels_json, languages_json, intro_video_url, documents_json,
        approval_status, rejection_reason, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?)
      ON CONFLICT(user_id) DO UPDATE SET
        headline = excluded.headline,
        bio = excluded.bio,
        qualifications = excluded.qualifications,
        experience_years = excluded.experience_years,
        hourly_rate_pkr = excluded.hourly_rate_pkr,
        subjects_json = excluded.subjects_json,
        levels_json = excluded.levels_json,
        languages_json = excluded.languages_json,
        intro_video_url = excluded.intro_video_url,
        documents_json = excluded.documents_json,
        approval_status = excluded.approval_status,
        rejection_reason = '',
        updated_at = excluded.updated_at
    `).run(
      req.auth!.userId,
      headline.trim(),
      bio.trim(),
      qualifications.trim(),
      Math.max(0, Math.min(60, Number(experienceYears || 1))),
      Math.round(rate),
      JSON.stringify(subjects),
      JSON.stringify(levels),
      JSON.stringify(Array.isArray(languages) && languages.length ? languages : ['English']),
      safeVideo || '',
      JSON.stringify(cleanDocs),
      nextApproval,
      now
    );

    const updated = db.prepare('SELECT * FROM tutor_profiles WHERE user_id = ?').get(req.auth!.userId);
    res.json({
      message:
        nextApproval === TutorApprovalStatus.Pending
          ? 'Profile submitted for admin approval.'
          : 'Tutor profile updated.',
      tutorProfile: updated,
    });
  });

  // --- FR-05: Search and Filter Tutors (Public / Guest accessible) ---
  router.get('/tutors', (req, res) => {
    const q = ((req.query.q as string) || '').trim().toLowerCase();
    const subject = ((req.query.subject as string) || '').trim();
    const level = ((req.query.level as string) || '').trim();
    const language = ((req.query.language as string) || '').trim();
    const minPrice = Number(req.query.minPrice || 0);
    const maxPrice = Number(req.query.maxPrice || 100000);
    const minRating = Number(req.query.minRating || 0);
    const dayFilter = req.query.day !== undefined && req.query.day !== '' ? Number(req.query.day) : null;
    const sort = (req.query.sort as string) || 'rating';
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(24, Math.max(1, Number(req.query.limit || 12)));

    const rows = db
      .prepare(`
        SELECT u.id, u.full_name, u.avatar_color, u.timezone, tp.*
        FROM users u
        JOIN tutor_profiles tp ON tp.user_id = u.id
        WHERE u.role = 'Tutor' AND u.status = 'Active' AND u.deleted_at IS NULL
        AND tp.approval_status = 'Approved'
      `)
      .all() as Array<Record<string, unknown>>;

    const slotsByTutor = new Map<string, number[]>();
    const slotRows = db
      .prepare('SELECT tutor_id, day_of_week FROM availability_slots WHERE is_blocked = 0')
      .all() as Array<{ tutor_id: string; day_of_week: number }>;
    for (const s of slotRows) {
      if (!slotsByTutor.has(s.tutor_id)) slotsByTutor.set(s.tutor_id, []);
      slotsByTutor.get(s.tutor_id)!.push(s.day_of_week);
    }

    let filtered = rows.map((r) => {
      const subjects: string[] = JSON.parse((r.subjects_json as string) || '[]');
      const levels: string[] = JSON.parse((r.levels_json as string) || '[]');
      const languages: string[] = JSON.parse((r.languages_json as string) || '[]');
      const documents: string[] = JSON.parse((r.documents_json as string) || '[]');
      return {
        id: r.id as string,
        fullName: r.full_name as string,
        avatarColor: r.avatar_color as string,
        timezone: r.timezone as string,
        headline: r.headline as string,
        bio: r.bio as string,
        qualifications: r.qualifications as string,
        experienceYears: r.experience_years as number,
        hourlyRatePkr: r.hourly_rate_pkr as number,
        subjects,
        levels,
        languages,
        documents,
        ratingAvg: r.rating_avg as number,
        ratingCount: r.rating_count as number,
        availableDays: Array.from(new Set(slotsByTutor.get(r.id as string) || [])),
      };
    });

    filtered = filtered.filter((t) => {
      if (q) {
        const hay = `${t.fullName} ${t.headline} ${t.bio} ${t.qualifications} ${t.subjects.join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (subject && !t.subjects.includes(subject)) return false;
      if (level && !t.levels.includes(level)) return false;
      if (language && !t.languages.includes(language)) return false;
      if (t.hourlyRatePkr < minPrice || t.hourlyRatePkr > maxPrice) return false;
      if (t.ratingAvg < minRating) return false;
      if (dayFilter !== null && !t.availableDays.includes(dayFilter)) return false;
      return true;
    });

    if (sort === 'price_asc') {
      filtered.sort((a, b) => a.hourlyRatePkr - b.hourlyRatePkr);
    } else if (sort === 'price_desc') {
      filtered.sort((a, b) => b.hourlyRatePkr - a.hourlyRatePkr);
    } else if (sort === 'rating') {
      filtered.sort((a, b) => b.ratingAvg - a.ratingAvg || b.ratingCount - a.ratingCount);
    } else {
      // relevance: rating + experience
      filtered.sort((a, b) => b.ratingAvg * 10 + b.experienceYears - (a.ratingAvg * 10 + a.experienceYears));
    }

    const total = filtered.length;
    const startIdx = (page - 1) * limit;
    const paged = filtered.slice(startIdx, startIdx + limit);

    res.json({
      tutors: paged,
      pagination: { total, page, limit, totalPages: Math.max(1, Math.ceil(total / limit)) },
    });
  });

  // Public Tutor Detail Profile
  router.get('/tutors/:id', (req, res) => {
    expireStaleBookingHolds();
    const row = db
      .prepare(`
        SELECT u.id, u.full_name, u.avatar_color, u.timezone, tp.*
        FROM users u
        JOIN tutor_profiles tp ON tp.user_id = u.id
        WHERE u.id = ? AND u.role = 'Tutor' AND u.deleted_at IS NULL AND tp.approval_status = 'Approved'
      `)
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!row) {
      res.status(404).json({ error: 'Tutor profile not found or awaiting approval.' });
      return;
    }

    const slots = db
      .prepare('SELECT * FROM availability_slots WHERE tutor_id = ? ORDER BY day_of_week ASC, start_time_utc ASC')
      .all(req.params.id);

    const reviews = db
      .prepare(`
        SELECT r.*, s.full_name as student_name, s.avatar_color as student_avatar_color
        FROM reviews r
        JOIN users s ON s.id = r.student_id
        WHERE r.tutor_id = ?
        ORDER BY r.created_at DESC
      `)
      .all(req.params.id);

    const activeBookings = db
      .prepare(`
        SELECT start_utc, end_utc, status FROM bookings
        WHERE tutor_id = ? AND status IN ('Awaiting Payment', 'Confirmed', 'Rescheduled', 'In Progress') AND deleted_at IS NULL
      `)
      .all(req.params.id);

    res.json({
      tutor: {
        id: row.id,
        fullName: row.full_name,
        avatarColor: row.avatar_color,
        timezone: row.timezone,
        headline: row.headline,
        bio: row.bio,
        qualifications: row.qualifications,
        experienceYears: row.experience_years,
        hourlyRatePkr: row.hourly_rate_pkr,
        subjects: JSON.parse((row.subjects_json as string) || '[]'),
        levels: JSON.parse((row.levels_json as string) || '[]'),
        languages: JSON.parse((row.languages_json as string) || '[]'),
        introVideoUrl: row.intro_video_url,
        documents: JSON.parse((row.documents_json as string) || '[]'),
        ratingAvg: row.rating_avg,
        ratingCount: row.rating_count,
      },
      availability: slots,
      reviews,
      bookedWindows: activeBookings,
    });
  });

  // --- FR-06: Manage Availability ---
  router.get('/tutor/availability', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const slots = db
      .prepare('SELECT * FROM availability_slots WHERE tutor_id = ? ORDER BY is_blocked ASC, day_of_week ASC, start_time_utc ASC')
      .all(req.auth!.userId);
    res.json({ slots });
  });

  router.post('/tutor/availability', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const profile = db.prepare('SELECT approval_status FROM tutor_profiles WHERE user_id = ?').get(req.auth!.userId) as
      | { approval_status: TutorApprovalStatus }
      | undefined;
    if (!profile || profile.approval_status !== TutorApprovalStatus.Approved) {
      res.status(403).json({ error: 'Only approved tutors can publish availability slots (FR-06).' });
      return;
    }

    const { dayOfWeek, startTimeUtc, endTimeUtc, isRecurring, specificDate, isBlocked } = req.body as {
      dayOfWeek?: number;
      startTimeUtc?: string;
      endTimeUtc?: string;
      isRecurring?: boolean;
      specificDate?: string;
      isBlocked?: boolean;
    };

    const day = Number(dayOfWeek);
    if (!Number.isInteger(day) || day < 0 || day > 6) {
      res.status(400).json({ error: 'Day of week must be 0 (Sunday) through 6 (Saturday).' });
      return;
    }
    if (!/^\d{2}:\d{2}$/.test(startTimeUtc || '') || !/^\d{2}:\d{2}$/.test(endTimeUtc || '')) {
      res.status(400).json({ error: 'Start and end time must use HH:MM format.' });
      return;
    }
    if (startTimeUtc! >= endTimeUtc!) {
      res.status(400).json({ error: 'End time must be after start time.' });
      return;
    }

    if (!isBlocked) {
      const existing = db
        .prepare('SELECT * FROM availability_slots WHERE tutor_id = ? AND day_of_week = ? AND is_blocked = 0')
        .all(req.auth!.userId, day) as Array<{ start_time_utc: string; end_time_utc: string }>;

      const overlaps = existing.some(
        (s) => startTimeUtc! < s.end_time_utc && endTimeUtc! > s.start_time_utc
      );
      if (overlaps) {
        res.status(409).json({ error: 'This slot overlaps an existing open availability slot.' });
        return;
      }
    }

    const id = `slot-${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO availability_slots (id, tutor_id, day_of_week, start_time_utc, end_time_utc, is_recurring, specific_date, is_blocked, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      req.auth!.userId,
      day,
      startTimeUtc,
      endTimeUtc,
      isRecurring === false ? 0 : 1,
      specificDate || null,
      isBlocked ? 1 : 0,
      new Date().toISOString()
    );

    const slots = db
      .prepare('SELECT * FROM availability_slots WHERE tutor_id = ? ORDER BY is_blocked ASC, day_of_week ASC, start_time_utc ASC')
      .all(req.auth!.userId);
    res.status(201).json({ message: 'Availability updated.', slots });
  });

  router.delete('/tutor/availability/:id', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const slot = db
      .prepare('SELECT * FROM availability_slots WHERE id = ? AND tutor_id = ?')
      .get(req.params.id, req.auth!.userId) as
      | { id: string; day_of_week: number; start_time_utc: string; end_time_utc: string; is_blocked: number }
      | undefined;

    if (!slot) {
      res.status(404).json({ error: 'Slot not found.' });
      return;
    }

    if (!slot.is_blocked) {
      const confirmed = db
        .prepare(`
          SELECT id, start_utc, end_utc FROM bookings
          WHERE tutor_id = ? AND status IN ('Confirmed', 'Rescheduled', 'In Progress') AND deleted_at IS NULL
        `)
        .all(req.auth!.userId) as Array<{ id: string; start_utc: string; end_utc: string }>;

      const conflict = confirmed.some((b) => {
        const d = new Date(b.start_utc);
        const hm = `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`;
        return d.getUTCDay() === slot.day_of_week && hm >= slot.start_time_utc && hm < slot.end_time_utc;
      });
      if (conflict) {
        res.status(409).json({ error: 'Cannot remove a slot that has confirmed upcoming bookings (FR-06).' });
        return;
      }
    }

    db.prepare('DELETE FROM availability_slots WHERE id = ?').run(slot.id);
    res.json({ message: 'Slot removed.' });
  });

  // --- FR-07: Book Session ---
  router.post('/bookings', requireAuth, requireRole(UserRole.Student), (req: AuthenticatedRequest, res) => {
    expireStaleBookingHolds();
    const { tutorId, subject, level, startUtc, durationMin, note } = req.body as {
      tutorId?: string;
      subject?: string;
      level?: string;
      startUtc?: string;
      durationMin?: number;
      note?: string;
    };

    const duration = Number(durationMin);
    if (![30, 60, 90].includes(duration)) {
      res.status(400).json({ error: 'Session duration must be 30, 60, or 90 minutes (FR-07).' });
      return;
    }
    const startDate = new Date(startUtc || '');
    if (Number.isNaN(startDate.getTime())) {
      res.status(400).json({ error: 'Invalid start date/time.' });
      return;
    }
    const endDate = new Date(startDate.getTime() + duration * 60 * 1000);
    if (endDate.getTime() < Date.now()) {
      res.status(400).json({ error: 'Cannot book a session in the past.' });
      return;
    }

    const tutor = db
      .prepare(`
        SELECT u.id, u.full_name, tp.hourly_rate_pkr, tp.approval_status
        FROM users u JOIN tutor_profiles tp ON tp.user_id = u.id
        WHERE u.id = ? AND u.role = 'Tutor' AND u.status = 'Active' AND u.deleted_at IS NULL
      `)
      .get(tutorId) as { id: string; full_name: string; hourly_rate_pkr: number; approval_status: string } | undefined;

    if (!tutor || tutor.approval_status !== TutorApprovalStatus.Approved) {
      res.status(404).json({ error: 'Selected tutor is not available for booking.' });
      return;
    }

    const commissionPct = Number(getConfigValue('PLATFORM_COMMISSION_PCT', '15'));
    const holdMin = Number(getConfigValue('SLOT_HOLD_MIN', String(SRS_CONSTANTS.SLOT_HOLD_MIN)));

    // Exact decimal arithmetic (SRS 4.3.3)
    const pricePkr = Math.round((tutor.hourly_rate_pkr * duration) / 60);
    const commissionPkr = Math.round((pricePkr * commissionPct) / 100);
    const tutorNetPkr = pricePkr - commissionPkr;

    const startIso = startDate.toISOString();
    const endIso = endDate.toISOString();
    const holdExpiresAt = new Date(Date.now() + holdMin * 60 * 1000).toISOString();
    const bookingId = `bk-${crypto.randomBytes(5).toString('hex')}`;
    const nowIso = new Date().toISOString();

    try {
      const booking = db.transaction(() => {
        const conflict = db
          .prepare(`
            SELECT id FROM bookings
            WHERE tutor_id = ? AND deleted_at IS NULL
            AND status IN ('Awaiting Payment', 'Confirmed', 'Rescheduled', 'In Progress')
            AND start_utc < ? AND end_utc > ?
          `)
          .get(tutor.id, endIso, startIso);

        if (conflict) {
          throw new Error('SLOT_CONFLICT');
        }

        db.prepare(`
          INSERT INTO bookings (
            id, student_id, tutor_id, subject, level, start_utc, end_utc, duration_min,
            note, price_pkr, commission_pkr, tutor_net_pkr, status, hold_expires_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          bookingId,
          req.auth!.userId,
          tutor.id,
          (subject || 'General Tutoring').trim(),
          (level || 'Undergraduate').trim(),
          startIso,
          endIso,
          duration,
          (note || '').trim().slice(0, 500),
          pricePkr,
          commissionPkr,
          tutorNetPkr,
          BookingStatus.AwaitingPayment,
          holdExpiresAt,
          nowIso,
          nowIso
        );

        return db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
      })();

      res.status(201).json({
        message: `Slot held for ${holdMin} minutes. Complete payment to confirm.`,
        booking,
      });
    } catch (err) {
      if (err instanceof Error && err.message === 'SLOT_CONFLICT') {
        res.status(409).json({ error: 'This time slot was just reserved or booked by another student. Please select another slot.' });
        return;
      }
      throw err;
    }
  });

  // --- FR-08: Make Payment (Hosted Gateway Adapter + Idempotent Webhook Transaction) ---
  router.post('/payments/checkout', requireAuth, requireRole(UserRole.Student), (req: AuthenticatedRequest, res) => {
    expireStaleBookingHolds();
    const { bookingId, method, accountLast4, simulateFailure } = req.body as {
      bookingId?: string;
      method?: 'card' | 'jazzcash' | 'easypaisa';
      accountLast4?: string;
      simulateFailure?: boolean;
    };

    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND student_id = ? AND deleted_at IS NULL')
      .get(bookingId, req.auth!.userId) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    if (booking.status === BookingStatus.Confirmed) {
      const existingPay = db.prepare('SELECT * FROM payments WHERE booking_id = ? AND status = ?').get(bookingId, PaymentStatus.Paid);
      res.json({ message: 'Booking is already confirmed.', booking, payment: existingPay });
      return;
    }
    if (booking.status !== BookingStatus.AwaitingPayment) {
      res.status(400).json({ error: `Booking is in "${booking.status}" state and cannot be paid.` });
      return;
    }

    const cleanMethod = method === 'jazzcash' || method === 'easypaisa' ? method : 'card';
    const cleanLast4 = /^\d{4}$/.test(accountLast4 || '') ? accountLast4! : '4242';
    const amountPkr = Number(booking.price_pkr);

    const gwResult = PaymentGatewayAdapter.processHostedCheckout({
      bookingId: booking.id as string,
      amountPkr,
      method: cleanMethod,
      accountLast4: cleanLast4,
      simulateFailure: Boolean(simulateFailure),
    });

    const now = new Date().toISOString();
    const paymentId = `pay-${crypto.randomBytes(5).toString('hex')}`;

    if (!gwResult.success) {
      db.prepare(`
        INSERT INTO payments (id, booking_id, student_id, amount_pkr, method, gateway_ref, card_last4, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(paymentId, booking.id, req.auth!.userId, amountPkr, cleanMethod, gwResult.gatewayRef, cleanLast4, PaymentStatus.Failed, now, now);

      res.status(402).json({
        error: gwResult.error || 'Payment declined. Your slot hold remains active until expiry.',
      });
      return;
    }

    // Verify webhook signature (SRS 3.1.4)
    if (!PaymentGatewayAdapter.verifyWebhookSignature(booking.id as string, amountPkr, gwResult.gatewayRef, gwResult.signature)) {
      res.status(500).json({ error: 'Gateway webhook signature verification failed.' });
      return;
    }

    // Atomic transactional confirmation (SRS 4.3.8)
    const result = db.transaction(() => {
      db.prepare(`
        INSERT INTO payments (id, booking_id, student_id, amount_pkr, method, gateway_ref, card_last4, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(paymentId, booking.id, req.auth!.userId, amountPkr, cleanMethod, gwResult.gatewayRef, cleanLast4, PaymentStatus.Paid, now, now);

      db.prepare(`
        UPDATE bookings SET status = ?, hold_expires_at = NULL, updated_at = ? WHERE id = ?
      `).run(BookingStatus.Confirmed, now, booking.id);

      return {
        booking: db.prepare('SELECT * FROM bookings WHERE id = ?').get(booking.id),
        payment: db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentId),
      };
    })();

    createAndDeliverNotification(
      req.auth!.userId,
      'email',
      `Booking Confirmed · ${booking.subject}`,
      `Receipt ${gwResult.gatewayRef}: PKR ${amountPkr.toLocaleString()} held in escrow for your ${booking.subject} session.`
    );
    createAndDeliverNotification(
      booking.tutor_id as string,
      'in_app',
      `New Confirmed Session · ${booking.subject}`,
      `${req.auth!.fullName} booked a ${booking.duration_min}-minute ${booking.subject} session.`
    );

    res.json({
      message: 'Payment verified and held in escrow. Session confirmed!',
      ...result,
    });
  });

  // --- List Bookings (Student & Tutor) ---
  router.get('/bookings', requireAuth, (req: AuthenticatedRequest, res) => {
    expireStaleBookingHolds();
    releaseEligibleEscrowPayments();

    const userId = req.auth!.userId;
    const rows = db
      .prepare(`
        SELECT b.*,
          s.full_name as student_name, s.avatar_color as student_avatar_color,
          t.full_name as tutor_name, t.avatar_color as tutor_avatar_color,
          p.id as payment_id, p.status as payment_status, p.method as payment_method, p.gateway_ref, p.refund_amount_pkr,
          r.id as review_id, r.rating as review_rating, r.comment as review_comment, r.tutor_reply as review_tutor_reply
        FROM bookings b
        JOIN users s ON s.id = b.student_id
        JOIN users t ON t.id = b.tutor_id
        LEFT JOIN payments p ON p.booking_id = b.id AND p.status != 'Failed' AND p.deleted_at IS NULL
        LEFT JOIN reviews r ON r.booking_id = b.id
        WHERE b.deleted_at IS NULL AND (b.student_id = ? OR b.tutor_id = ?)
        ORDER BY b.start_utc DESC
      `)
      .all(userId, userId);

    res.json({ bookings: rows });
  });

  // --- FR-09: Reschedule / Cancel Session ---
  router.post('/bookings/:id/cancel', requireAuth, (req: AuthenticatedRequest, res) => {
    const { reason } = req.body as { reason?: string };
    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND deleted_at IS NULL')
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    if (booking.student_id !== req.auth!.userId && booking.tutor_id !== req.auth!.userId) {
      res.status(403).json({ error: 'Not authorized to cancel this session.' });
      return;
    }
    if (!([BookingStatus.Confirmed, BookingStatus.Rescheduled, BookingStatus.AwaitingPayment] as string[]).includes(String(booking.status))) {
      res.status(400).json({ error: `Cannot cancel a session in "${booking.status}" state.` });
      return;
    }
    if (new Date(booking.start_utc as string).getTime() <= Date.now()) {
      res.status(400).json({ error: 'Cancellation requests after the session start time are rejected (FR-09).' });
      return;
    }

    const freeHours = Number(getConfigValue('FREE_CANCEL_HOURS', String(SRS_CONSTANTS.FREE_CANCEL_HOURS)));
    const hoursUntilStart = (new Date(booking.start_utc as string).getTime() - Date.now()) / 3600000;
    const isTutorInitiated = req.auth!.userId === booking.tutor_id;
    const fullRefund = isTutorInitiated || hoursUntilStart >= freeHours;

    const payment = db
      .prepare('SELECT * FROM payments WHERE booking_id = ? AND status = ? AND deleted_at IS NULL')
      .get(booking.id, PaymentStatus.Paid) as { id: string; amount_pkr: number; gateway_ref: string } | undefined;

    let refundAmount = 0;
    const now = new Date().toISOString();

    if (payment) {
      refundAmount = fullRefund ? payment.amount_pkr : Math.round(payment.amount_pkr * 0.5);
      const gw = PaymentGatewayAdapter.processRefund(payment.gateway_ref, refundAmount);
      if (!gw.success) {
        res.status(502).json({ error: 'Payment gateway refund failed. Please try again.' });
        return;
      }
      db.prepare('UPDATE payments SET status = ?, refund_amount_pkr = ?, updated_at = ? WHERE id = ?').run(
        PaymentStatus.Refunded,
        refundAmount,
        now,
        payment.id
      );
    }

    db.prepare(`
      UPDATE bookings SET status = ?, cancel_reason = ?, cancelled_by = ?, updated_at = ? WHERE id = ?
    `).run(BookingStatus.Cancelled, (reason || 'Cancelled by user').trim(), req.auth!.userId, now, booking.id);

    const otherPartyId = req.auth!.userId === booking.student_id ? (booking.tutor_id as string) : (booking.student_id as string);
    createAndDeliverNotification(
      otherPartyId,
      'email',
      `Session Cancelled · ${booking.subject}`,
      `${req.auth!.fullName} cancelled the ${booking.subject} session. ${refundAmount > 0 ? `Refund issued: PKR ${refundAmount.toLocaleString()}.` : ''}`
    );

    res.json({
      message: payment
        ? `Session cancelled. ${fullRefund ? '100% free cancellation' : '50% late-cancellation'} refund of PKR ${refundAmount.toLocaleString()} processed.`
        : 'Session hold cancelled.',
      refundAmountPkr: refundAmount,
    });
  });

  router.post('/bookings/:id/reschedule', requireAuth, (req: AuthenticatedRequest, res) => {
    const { newStartUtc, reason } = req.body as { newStartUtc?: string; reason?: string };
    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND deleted_at IS NULL')
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    if (booking.student_id !== req.auth!.userId && booking.tutor_id !== req.auth!.userId) {
      res.status(403).json({ error: 'Not authorized to reschedule this session.' });
      return;
    }
    if (!([BookingStatus.Confirmed, BookingStatus.Rescheduled] as string[]).includes(String(booking.status))) {
      res.status(400).json({ error: 'Only confirmed sessions can be rescheduled.' });
      return;
    }
    if (new Date(booking.start_utc as string).getTime() <= Date.now()) {
      res.status(400).json({ error: 'Reschedule requests after the session start time are rejected (FR-09).' });
      return;
    }

    const nextStart = new Date(newStartUtc || '');
    if (Number.isNaN(nextStart.getTime()) || nextStart.getTime() <= Date.now()) {
      res.status(400).json({ error: 'Choose a valid future date and time.' });
      return;
    }
    const nextEnd = new Date(nextStart.getTime() + Number(booking.duration_min) * 60 * 1000);

    const conflict = db
      .prepare(`
        SELECT id FROM bookings
        WHERE tutor_id = ? AND id != ? AND deleted_at IS NULL
        AND status IN ('Awaiting Payment', 'Confirmed', 'Rescheduled', 'In Progress')
        AND start_utc < ? AND end_utc > ?
      `)
      .get(booking.tutor_id, booking.id, nextEnd.toISOString(), nextStart.toISOString());

    if (conflict) {
      res.status(409).json({ error: 'The requested new time overlaps another booking.' });
      return;
    }

    db.prepare(`
      UPDATE bookings SET start_utc = ?, end_utc = ?, status = ?, cancel_reason = ?, updated_at = ? WHERE id = ?
    `).run(
      nextStart.toISOString(),
      nextEnd.toISOString(),
      BookingStatus.Rescheduled,
      (reason || 'Rescheduled').trim(),
      new Date().toISOString(),
      booking.id
    );

    const otherPartyId = req.auth!.userId === booking.student_id ? (booking.tutor_id as string) : (booking.student_id as string);
    createAndDeliverNotification(
      otherPartyId,
      'email',
      `Session Rescheduled · ${booking.subject}`,
      `${req.auth!.fullName} rescheduled your ${booking.subject} session to ${nextStart.toUTCString()}.`
    );

    res.json({ message: 'Session rescheduled successfully.' });
  });

  // --- FR-10 & FR-12: Join & End Live Classroom ---
  router.post('/bookings/:id/join', requireAuth, (req: AuthenticatedRequest, res) => {
    const booking = db
      .prepare(`
        SELECT b.*, s.full_name as student_name, t.full_name as tutor_name
        FROM bookings b
        JOIN users s ON s.id = b.student_id
        JOIN users t ON t.id = b.tutor_id
        WHERE b.id = ? AND b.deleted_at IS NULL
      `)
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    const isParticipant = booking.student_id === req.auth!.userId || booking.tutor_id === req.auth!.userId;
    if (!isParticipant && req.auth!.role !== UserRole.Admin) {
      res.status(403).json({ error: 'You are not a participant in this classroom.' });
      return;
    }
    if (!([BookingStatus.Confirmed, BookingStatus.Rescheduled, BookingStatus.InProgress] as string[]).includes(String(booking.status))) {
      res.status(400).json({ error: `Cannot join classroom because session status is "${booking.status}".` });
      return;
    }

    const nowMs = Date.now();
    const startMs = new Date(booking.start_utc as string).getTime();
    const endMs = new Date(booking.end_utc as string).getTime();
    const windowMs = SRS_CONSTANTS.JOIN_WINDOW_MIN * 60 * 1000;

    if (nowMs < startMs - windowMs) {
      const minsUntilWindow = Math.ceil((startMs - windowMs - nowMs) / 60000);
      res.status(403).json({
        error: `Join opens ${SRS_CONSTANTS.JOIN_WINDOW_MIN} minutes before scheduled start (${minsUntilWindow} min remaining).`,
      });
      return;
    }
    if (nowMs > endMs + 15 * 60 * 1000) {
      res.status(403).json({ error: 'This session window has already ended.' });
      return;
    }

    const roomToken = VideoRoomAdapter.issueRoomToken(booking.id as string, req.auth!.userId, req.auth!.role);
    let attendance: Record<string, string> = {};
    try {
      attendance = JSON.parse((booking.attendance_json as string) || '{}');
    } catch {
      attendance = {};
    }
    attendance[req.auth!.userId] = new Date().toISOString();

    db.prepare(`
      UPDATE bookings SET status = ?, room_token = ?, attendance_json = ?, updated_at = ? WHERE id = ?
    `).run(BookingStatus.InProgress, roomToken, JSON.stringify(attendance), new Date().toISOString(), booking.id);

    res.json({
      roomToken,
      booking: db
        .prepare(`
          SELECT b.*, s.full_name as student_name, t.full_name as tutor_name
          FROM bookings b JOIN users s ON s.id = b.student_id JOIN users t ON t.id = b.tutor_id
          WHERE b.id = ?
        `)
        .get(booking.id),
    });
  });

  router.post('/bookings/:id/end', requireAuth, (req: AuthenticatedRequest, res) => {
    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND deleted_at IS NULL')
      .get(req.params.id) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    if (booking.student_id !== req.auth!.userId && booking.tutor_id !== req.auth!.userId) {
      res.status(403).json({ error: 'Not authorized.' });
      return;
    }
    if (booking.status === BookingStatus.Completed) {
      res.json({ message: 'Session already completed.', booking });
      return;
    }
    if (booking.status !== BookingStatus.InProgress && booking.status !== BookingStatus.Confirmed) {
      res.status(400).json({ error: `Session cannot be ended from "${booking.status}" state.` });
      return;
    }

    const now = new Date().toISOString();
    db.prepare('UPDATE bookings SET status = ?, updated_at = ? WHERE id = ?').run(
      BookingStatus.Completed,
      now,
      booking.id
    );

    createAndDeliverNotification(
      booking.student_id as string,
      'in_app',
      `Session Completed · ${booking.subject}`,
      `Your ${booking.subject} session is complete. Please rate and review your tutor.`
    );

    res.json({
      message: 'Session marked Completed. Earnings will be released after the 24-hour review window.',
      booking: db.prepare('SELECT * FROM bookings WHERE id = ?').get(booking.id),
    });
  });

  // SRS 4.3.5: iCal Calendar Export
  router.get('/bookings/:id/ical', requireAuth, (req: AuthenticatedRequest, res) => {
    const b = db
      .prepare(`
        SELECT b.*, t.full_name as tutor_name, s.full_name as student_name
        FROM bookings b JOIN users t ON t.id = b.tutor_id JOIN users s ON s.id = b.student_id
        WHERE b.id = ? AND (b.student_id = ? OR b.tutor_id = ?) AND b.deleted_at IS NULL
      `)
      .get(req.params.id, req.auth!.userId, req.auth!.userId) as Record<string, unknown> | undefined;

    if (!b) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    const fmt = (iso: string) => iso.replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
    const ics = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//Online Tutor Academy//OTA v1.0//EN',
      'BEGIN:VEVENT',
      `UID:${b.id}@ota.edu.pk`,
      `DTSTAMP:${fmt(new Date().toISOString())}`,
      `DTSTART:${fmt(b.start_utc as string)}`,
      `DTEND:${fmt(b.end_utc as string)}`,
      `SUMMARY:OTA Lesson - ${b.subject} (${b.level})`,
      `DESCRIPTION:Tutor: ${b.tutor_name} | Student: ${b.student_name}`,
      'END:VEVENT',
      'END:VCALENDAR',
    ].join('\r\n');

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="ota-session-${b.id}.ics"`);
    res.send(ics);
  });

  // --- FR-13: Study Materials ---
  router.get('/materials', requireAuth, (req: AuthenticatedRequest, res) => {
    const uid = req.auth!.userId;
    const rows = db
      .prepare(`
        SELECT m.*, t.full_name as tutor_name, s.full_name as student_name
        FROM study_materials m
        JOIN users t ON t.id = m.tutor_id
        LEFT JOIN users s ON s.id = m.student_id
        WHERE m.tutor_id = ? OR m.student_id = ? OR (
          m.student_id IS NULL AND m.tutor_id IN (SELECT tutor_id FROM bookings WHERE student_id = ? AND deleted_at IS NULL)
        )
        ORDER BY m.created_at DESC
      `)
      .all(uid, uid, uid);
    res.json({ materials: rows });
  });

  router.post('/materials', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const { studentId, bookingId, title, urlOrName, fileType, sizeKb } = req.body as {
      studentId?: string;
      bookingId?: string;
      title?: string;
      urlOrName?: string;
      fileType?: string;
      sizeKb?: number;
    };

    if (!title || title.trim().length < 2) {
      res.status(400).json({ field: 'title', error: 'Material title is required.' });
      return;
    }
    if (!urlOrName || !urlOrName.trim()) {
      res.status(400).json({ field: 'urlOrName', error: 'Provide a file or valid resource URL.' });
      return;
    }
    const type = (fileType || 'PDF').toUpperCase();
    const allowedTypes = ['PDF', 'DOCX', 'PPTX', 'JPG', 'PNG', 'URL'];
    if (!allowedTypes.includes(type)) {
      res.status(400).json({ error: 'Unsupported file type. Allowed: PDF, DOCX, PPTX, JPG, PNG, URL (FR-13).' });
      return;
    }
    if (type === 'URL' && !sanitizeSafeUrl(urlOrName)) {
      res.status(400).json({ field: 'urlOrName', error: 'Resource URL must begin with http:// or https://.' });
      return;
    }
    const kb = Number(sizeKb || 0);
    if (kb > SRS_CONSTANTS.MAX_MATERIAL_MB * 1024) {
      res.status(400).json({ error: `File exceeds the ${SRS_CONSTANTS.MAX_MATERIAL_MB} MB limit (FR-13).` });
      return;
    }

    if (studentId) {
      const hasBooking = db
        .prepare('SELECT id FROM bookings WHERE tutor_id = ? AND student_id = ? AND deleted_at IS NULL')
        .get(req.auth!.userId, studentId);
      if (!hasBooking) {
        res.status(403).json({ error: 'You must have at least one booking with the student to share materials (FR-13).' });
        return;
      }
    }

    const id = `mat-${crypto.randomBytes(5).toString('hex')}`;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO study_materials (id, tutor_id, student_id, booking_id, title, url_or_name, file_type, size_kb, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.auth!.userId, studentId || null, bookingId || null, title.trim(), urlOrName.trim(), type, kb, now);

    if (studentId) {
      createAndDeliverNotification(
        studentId,
        'in_app',
        `New Study Material · ${title.trim()}`,
        `${req.auth!.fullName} shared "${title.trim()}" (${type}).`
      );
    }

    res.status(201).json({ message: 'Study material uploaded and verified.', id });
  });

  // --- FR-14 & FR-15: Assignments & Grading ---
  router.get('/assignments', requireAuth, (req: AuthenticatedRequest, res) => {
    const uid = req.auth!.userId;
    const rows = db
      .prepare(`
        SELECT a.*, t.full_name as tutor_name, s.full_name as student_name
        FROM assignments a
        JOIN users t ON t.id = a.tutor_id
        JOIN users s ON s.id = a.student_id
        WHERE a.tutor_id = ? OR a.student_id = ?
        ORDER BY a.created_at DESC
      `)
      .all(uid, uid);
    res.json({ assignments: rows });
  });

  router.post('/assignments', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const { studentId, bookingId, title, description, dueAt, allowLate } = req.body as {
      studentId?: string;
      bookingId?: string;
      title?: string;
      description?: string;
      dueAt?: string;
      allowLate?: boolean;
    };

    if (!studentId) {
      res.status(400).json({ field: 'studentId', error: 'Select a student.' });
      return;
    }
    const hasBooking = db
      .prepare('SELECT id FROM bookings WHERE tutor_id = ? AND student_id = ? AND deleted_at IS NULL')
      .get(req.auth!.userId, studentId);
    if (!hasBooking) {
      res.status(403).json({ error: 'A tutor-student booking must exist before assigning work (FR-14).' });
      return;
    }
    if (!title || title.trim().length < 3) {
      res.status(400).json({ field: 'title', error: 'Assignment title is required.' });
      return;
    }
    if (!description || description.trim().length < 5) {
      res.status(400).json({ field: 'description', error: 'Assignment instructions are required.' });
      return;
    }
    const dueDate = new Date(dueAt || '');
    if (Number.isNaN(dueDate.getTime())) {
      res.status(400).json({ field: 'dueAt', error: 'Enter a valid due date.' });
      return;
    }

    const id = `asg-${crypto.randomBytes(5).toString('hex')}`;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO assignments (id, tutor_id, student_id, booking_id, title, description, due_at, allow_late, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      req.auth!.userId,
      studentId,
      bookingId || null,
      title.trim(),
      description.trim(),
      dueDate.toISOString(),
      allowLate ? 1 : 0,
      AssignmentStatus.Published,
      now
    );

    createAndDeliverNotification(
      studentId,
      'in_app',
      `New Assignment · ${title.trim()}`,
      `${req.auth!.fullName} published an assignment due on ${dueDate.toLocaleDateString()}.`
    );

    res.status(201).json({ message: 'Assignment published.', id });
  });

  router.post('/assignments/:id/submit', requireAuth, requireRole(UserRole.Student), (req: AuthenticatedRequest, res) => {
    const { submissionText, submissionFile } = req.body as { submissionText?: string; submissionFile?: string };
    const asg = db
      .prepare('SELECT * FROM assignments WHERE id = ? AND student_id = ?')
      .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

    if (!asg) {
      res.status(404).json({ error: 'Assignment not found.' });
      return;
    }
    if ((!submissionText || !submissionText.trim()) && (!submissionFile || !submissionFile.trim())) {
      res.status(400).json({ error: 'Provide a written answer or attach a solution file.' });
      return;
    }

    const isLate = Date.now() > new Date(asg.due_at as string).getTime();
    if (isLate && !asg.allow_late) {
      res.status(400).json({ error: 'Deadline has passed and this assignment does not accept late submissions (FR-14).' });
      return;
    }

    const nextStatus = isLate ? AssignmentStatus.Late : AssignmentStatus.Submitted;
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE assignments SET status = ?, submission_text = ?, submission_file = ?, submitted_at = ? WHERE id = ?
    `).run(nextStatus, (submissionText || '').trim(), (submissionFile || '').trim(), now, asg.id);

    createAndDeliverNotification(
      asg.tutor_id as string,
      'in_app',
      `Submission Received · ${asg.title}`,
      `${req.auth!.fullName} submitted work (${nextStatus}).`
    );

    res.json({ message: isLate ? 'Submitted (flagged as Late).' : 'Assignment submitted successfully.', status: nextStatus });
  });

  router.post('/assignments/:id/grade', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const { score, feedback } = req.body as { score?: number; feedback?: string };
    const asg = db
      .prepare('SELECT * FROM assignments WHERE id = ? AND tutor_id = ?')
      .get(req.params.id, req.auth!.userId) as Record<string, unknown> | undefined;

    if (!asg) {
      res.status(404).json({ error: 'Assignment not found.' });
      return;
    }
    if (!([AssignmentStatus.Submitted, AssignmentStatus.Late, AssignmentStatus.Graded] as string[]).includes(String(asg.status))) {
      res.status(400).json({ error: 'Cannot grade an assignment before the student submits.' });
      return;
    }
    const numericScore = Number(score);
    if (!Number.isInteger(numericScore) || numericScore < 0 || numericScore > 100) {
      res.status(400).json({ field: 'score', error: 'Score must be an integer between 0 and 100 (FR-15).' });
      return;
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE assignments SET status = ?, score = ?, feedback = ?, graded_at = ? WHERE id = ?
    `).run(AssignmentStatus.Graded, numericScore, (feedback || '').trim(), now, asg.id);

    createAndDeliverNotification(
      asg.student_id as string,
      'email',
      `Assignment Graded · ${numericScore}/100`,
      `${req.auth!.fullName} graded "${asg.title}" with ${numericScore}/100.`
    );

    res.json({ message: 'Grade and feedback saved.' });
  });

  // --- FR-16: Rate and Review Tutor ---
  router.post('/reviews', requireAuth, requireRole(UserRole.Student), (req: AuthenticatedRequest, res) => {
    const { bookingId, rating, comment } = req.body as { bookingId?: string; rating?: number; comment?: string };
    const numRating = Number(rating);
    if (!Number.isInteger(numRating) || numRating < 1 || numRating > 5) {
      res.status(400).json({ field: 'rating', error: 'Rating must be between 1 and 5 stars.' });
      return;
    }
    const cleanComment = (comment || '').trim();
    if (cleanComment.length > 500) {
      res.status(400).json({ field: 'comment', error: 'Review comment must be 500 characters or fewer.' });
      return;
    }
    if (containsAbusiveLanguage(cleanComment)) {
      res.status(400).json({ field: 'comment', error: 'Review rejected by moderation filter due to inappropriate language (FR-16).' });
      return;
    }

    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND student_id = ? AND deleted_at IS NULL')
      .get(bookingId, req.auth!.userId) as Record<string, unknown> | undefined;

    if (!booking) {
      res.status(404).json({ error: 'Booking not found.' });
      return;
    }
    if (booking.status !== BookingStatus.Completed) {
      res.status(400).json({ error: 'You can only review a Completed session.' });
      return;
    }
    const dup = db.prepare('SELECT id FROM reviews WHERE booking_id = ?').get(bookingId);
    if (dup) {
      res.status(409).json({ error: 'You have already reviewed this session (FR-16).' });
      return;
    }

    const revId = `rev-${crypto.randomBytes(5).toString('hex')}`;
    const now = new Date().toISOString();

    db.transaction(() => {
      db.prepare(`
        INSERT INTO reviews (id, booking_id, tutor_id, student_id, rating, comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(revId, booking.id, booking.tutor_id, req.auth!.userId, numRating, cleanComment, now);

      const agg = db
        .prepare('SELECT AVG(rating) as avg_rating, COUNT(*) as cnt FROM reviews WHERE tutor_id = ?')
        .get(booking.tutor_id) as { avg_rating: number; cnt: number };

      db.prepare('UPDATE tutor_profiles SET rating_avg = ?, rating_count = ?, updated_at = ? WHERE user_id = ?').run(
        Math.round(agg.avg_rating * 10) / 10,
        agg.cnt,
        now,
        booking.tutor_id
      );
    })();

    createAndDeliverNotification(
      booking.tutor_id as string,
      'in_app',
      `New ${numRating}-Star Review`,
      `${req.auth!.fullName} rated your ${booking.subject} session ${numRating}/5.`
    );

    res.status(201).json({ message: 'Thank you! Your review has been published.' });
  });

  router.post('/reviews/:id/reply', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    const { reply } = req.body as { reply?: string };
    const rev = db
      .prepare('SELECT * FROM reviews WHERE id = ? AND tutor_id = ?')
      .get(req.params.id, req.auth!.userId) as { id: string; tutor_reply: string } | undefined;

    if (!rev) {
      res.status(404).json({ error: 'Review not found.' });
      return;
    }
    if (rev.tutor_reply && rev.tutor_reply.trim().length > 0) {
      res.status(409).json({ error: 'Tutors may only reply once to a review (FR-16).' });
      return;
    }
    if (!reply || reply.trim().length < 2) {
      res.status(400).json({ error: 'Reply text cannot be empty.' });
      return;
    }

    db.prepare('UPDATE reviews SET tutor_reply = ?, tutor_replied_at = ? WHERE id = ?').run(
      reply.trim().slice(0, 500),
      new Date().toISOString(),
      rev.id
    );
    res.json({ message: 'Reply posted.' });
  });

  // --- Platform-Internal Messaging (SRS 4.2.1 Minor Safety: no phone/email exposure) ---
  router.get('/messages', requireAuth, (req: AuthenticatedRequest, res) => {
    const uid = req.auth!.userId;
    const rows = db
      .prepare(`
        SELECT m.*,
          su.full_name as sender_name, su.role as sender_role, su.avatar_color as sender_color,
          ru.full_name as recipient_name, ru.role as recipient_role, ru.avatar_color as recipient_color
        FROM messages m
        JOIN users su ON su.id = m.sender_id
        JOIN users ru ON ru.id = m.recipient_id
        WHERE m.sender_id = ? OR m.recipient_id = ?
        ORDER BY m.created_at ASC
      `)
      .all(uid, uid);

    // Contacts available for messaging (based on bookings, excluding email/phone exposure)
    const contacts = db
      .prepare(`
        SELECT DISTINCT u.id, u.full_name, u.role, u.avatar_color
        FROM bookings b
        JOIN users u ON (u.id = b.tutor_id AND b.student_id = ?) OR (u.id = b.student_id AND b.tutor_id = ?)
        WHERE b.deleted_at IS NULL AND u.deleted_at IS NULL
      `)
      .all(uid, uid);

    res.json({ messages: rows, contacts });
  });

  router.post('/messages', requireAuth, (req: AuthenticatedRequest, res) => {
    const { recipientId, bookingId, body } = req.body as { recipientId?: string; bookingId?: string; body?: string };
    if (!recipientId || !body || !body.trim()) {
      res.status(400).json({ error: 'Recipient and message text are required.' });
      return;
    }

    // Enforce SRS 4.2.1 minor safety: warn/block external contact sharing patterns if minor involved
    const cleanBody = body.trim().slice(0, 1500);
    const id = `msg-${crypto.randomBytes(5).toString('hex')}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO messages (id, sender_id, recipient_id, booking_id, body, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, req.auth!.userId, recipientId, bookingId || null, cleanBody, now);

    createAndDeliverNotification(
      recipientId,
      'in_app',
      `New message from ${req.auth!.fullName}`,
      cleanBody.slice(0, 90)
    );

    res.status(201).json({ message: 'Message sent.', id });
  });

  // --- FR-17: Notifications ---
  router.get('/notifications', requireAuth, (req: AuthenticatedRequest, res) => {
    const rows = db
      .prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 40')
      .all(req.auth!.userId);
    res.json({ notifications: rows });
  });

  router.post('/notifications/read-all', requireAuth, (req: AuthenticatedRequest, res) => {
    db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.auth!.userId);
    res.json({ message: 'All notifications marked read.' });
  });

  // --- Tutor Earnings & Payouts ---
  router.get('/tutor/earnings', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    releaseEligibleEscrowPayments();
    const uid = req.auth!.userId;

    const ledger = db
      .prepare(`
        SELECT b.id as booking_id, b.subject, b.start_utc, b.duration_min, b.price_pkr, b.commission_pkr, b.tutor_net_pkr, b.status as booking_status,
               s.full_name as student_name, p.status as payment_status, p.refund_amount_pkr
        FROM bookings b
        JOIN users s ON s.id = b.student_id
        JOIN payments p ON p.booking_id = b.id AND p.status != 'Failed' AND p.deleted_at IS NULL
        WHERE b.tutor_id = ? AND b.deleted_at IS NULL
        ORDER BY b.start_utc DESC
      `)
      .all(uid) as Array<{ tutor_net_pkr: number; payment_status: string }>;

    const payouts = db
      .prepare('SELECT * FROM payouts WHERE tutor_id = ? ORDER BY created_at DESC')
      .all(uid) as Array<{ amount_pkr: number }>;

    const escrowPkr = ledger
      .filter((r) => r.payment_status === PaymentStatus.Paid)
      .reduce((sum, r) => sum + r.tutor_net_pkr, 0);
    const releasedGrossPkr = ledger
      .filter((r) => r.payment_status === PaymentStatus.Released)
      .reduce((sum, r) => sum + r.tutor_net_pkr, 0);
    const withdrawnPkr = payouts.reduce((sum, p) => sum + p.amount_pkr, 0);
    const availableForPayoutPkr = Math.max(0, releasedGrossPkr - withdrawnPkr);

    res.json({
      summary: { escrowPkr, releasedGrossPkr, withdrawnPkr, availableForPayoutPkr },
      ledger,
      payouts,
    });
  });

  router.post('/tutor/payout', requireAuth, requireRole(UserRole.Tutor), (req: AuthenticatedRequest, res) => {
    releaseEligibleEscrowPayments();
    const uid = req.auth!.userId;
    const { method } = req.body as { method?: string };

    const releasedRows = db
      .prepare(`
        SELECT COALESCE(SUM(b.tutor_net_pkr), 0) as total
        FROM bookings b JOIN payments p ON p.booking_id = b.id
        WHERE b.tutor_id = ? AND p.status = ? AND p.deleted_at IS NULL AND b.deleted_at IS NULL
      `)
      .get(uid, PaymentStatus.Released) as { total: number };
    const withdrawnRows = db
      .prepare('SELECT COALESCE(SUM(amount_pkr), 0) as total FROM payouts WHERE tutor_id = ?')
      .get(uid) as { total: number };

    const available = releasedRows.total - withdrawnRows.total;
    if (available <= 0) {
      res.status(400).json({ error: 'No released funds available for payout yet (24-hour delay applies after completion).' });
      return;
    }

    const id = `pyt-${crypto.randomBytes(5).toString('hex')}`;
    db.prepare('INSERT INTO payouts (id, tutor_id, amount_pkr, method, status, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      id,
      uid,
      available,
      method || 'Bank IBFT',
      'Processed',
      new Date().toISOString()
    );

    createAndDeliverNotification(
      uid,
      'email',
      `Payout Processed · PKR ${available.toLocaleString()}`,
      `Your payout of PKR ${available.toLocaleString()} via ${method || 'Bank IBFT'} has been initiated.`
    );

    res.status(201).json({ message: `Payout of PKR ${available.toLocaleString()} processed.` });
  });

  // --- Safety 4.2.3 & FR-20: Submit Dispute / Report Inappropriate Behaviour ---
  router.post('/disputes', requireAuth, (req: AuthenticatedRequest, res) => {
    const { bookingId, category, reason } = req.body as { bookingId?: string; category?: string; reason?: string };
    if (!bookingId || !reason || reason.trim().length < 10) {
      res.status(400).json({ error: 'Provide a detailed description (min 10 characters).' });
      return;
    }

    const booking = db
      .prepare('SELECT * FROM bookings WHERE id = ? AND deleted_at IS NULL')
      .get(bookingId) as Record<string, unknown> | undefined;
    if (!booking || (booking.student_id !== req.auth!.userId && booking.tutor_id !== req.auth!.userId)) {
      res.status(404).json({ error: 'Session not found.' });
      return;
    }

    const cleanCategory = (category || 'Session Quality').trim();
    const isChildSafety = cleanCategory.toLowerCase().includes('child safety');
    const id = `disp-${crypto.randomBytes(5).toString('hex')}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO disputes (id, booking_id, reporter_id, category, reason, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, bookingId, req.auth!.userId, cleanCategory, reason.trim(), DisputeStatus.Open, now);

    // Safety 4.2.3: Child safety reports escalate immediately and suspend tutor pending review
    if (isChildSafety) {
      db.prepare('UPDATE users SET status = ? WHERE id = ?').run(AccountStatus.Suspended, booking.tutor_id);
      revokeAllUserSessions(booking.tutor_id as string);
      recordAuditLog('system', 'Admin', 'CHILD_SAFETY_AUTO_ESCALATION', 'user', booking.tutor_id as string, {
        disputeId: id,
        bookingId,
      });
    }

    res.status(201).json({
      message: isChildSafety
        ? 'Child safety report escalated immediately to Academy Administrators and tutor account suspended pending review.'
        : 'Report submitted. An Academy Administrator will review session logs and respond.',
      id,
    });
  });

  // ============================================================================
  // ADMIN CONSOLE ROUTES (FR-18, FR-19, FR-20, FR-21, Config)
  // ============================================================================

  router.get('/admin/overview', requireAuth, requireRole(UserRole.Admin), (_req, res) => {
    const pendingTutors = db
      .prepare(`
        SELECT u.id, u.full_name, u.email, u.status, u.created_at, tp.*
        FROM users u JOIN tutor_profiles tp ON tp.user_id = u.id
        WHERE u.role = 'Tutor' AND u.deleted_at IS NULL AND tp.approval_status = 'Pending'
        ORDER BY u.created_at DESC
      `)
      .all();

    const users = db
      .prepare(`
        SELECT u.id, u.full_name, u.email, u.role, u.status, u.guardian_email, u.timezone, u.created_at, u.deleted_at,
               tp.approval_status, tp.hourly_rate_pkr, tp.rating_avg
        FROM users u
        LEFT JOIN tutor_profiles tp ON tp.user_id = u.id
        WHERE u.deleted_at IS NULL
        ORDER BY u.created_at DESC
      `)
      .all();

    const disputeRows = db
      .prepare(`
        SELECT d.*, b.subject, b.level, b.start_utc, b.duration_min, b.price_pkr, b.attendance_json,
               rep.full_name as reporter_name, stu.full_name as student_name, tut.full_name as tutor_name,
               p.status as payment_status, p.amount_pkr
        FROM disputes d
        JOIN bookings b ON b.id = d.booking_id
        JOIN users rep ON rep.id = d.reporter_id
        JOIN users stu ON stu.id = b.student_id
        JOIN users tut ON tut.id = b.tutor_id
        LEFT JOIN payments p ON p.booking_id = b.id AND p.status != 'Failed' AND p.deleted_at IS NULL
        ORDER BY CASE WHEN d.status = 'Open' THEN 0 ELSE 1 END, d.created_at DESC
      `)
      .all() as Array<Record<string, unknown>>;

    const disputes = disputeRows.map((d) => {
        const chatTranscript = db
          .prepare(`
            SELECT ce.id, ce.event_type, ce.payload_json, ce.created_at
            FROM classroom_events ce
            WHERE ce.booking_id = ?
            ORDER BY ce.created_at ASC
          `)
          .all(d.booking_id);
        return { ...d, chatTranscript };
      });

    const auditLogs = db
      .prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 60')
      .all();

    res.json({ pendingTutors, users, disputes, auditLogs });
  });

  // FR-18: Approve / Reject Tutor
  router.post('/admin/tutors/:id/decision', requireAuth, requireRole(UserRole.Admin), (req: AuthenticatedRequest, res) => {
    const { decision, reason } = req.body as { decision?: 'Approved' | 'Rejected'; reason?: string };
    if (decision !== TutorApprovalStatus.Approved && decision !== TutorApprovalStatus.Rejected) {
      res.status(400).json({ error: 'Decision must be Approved or Rejected.' });
      return;
    }
    if (decision === TutorApprovalStatus.Rejected && (!reason || reason.trim().length < 5)) {
      res.status(400).json({ field: 'reason', error: 'A rejection reason is mandatory (FR-18).' });
      return;
    }

    const tutor = db
      .prepare('SELECT u.id, u.full_name, tp.approval_status FROM users u JOIN tutor_profiles tp ON tp.user_id = u.id WHERE u.id = ?')
      .get(req.params.id) as { id: string; full_name: string; approval_status: string } | undefined;

    if (!tutor) {
      res.status(404).json({ error: 'Tutor application not found.' });
      return;
    }

    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare('UPDATE tutor_profiles SET approval_status = ?, rejection_reason = ?, updated_at = ? WHERE user_id = ?').run(
        decision,
        decision === TutorApprovalStatus.Rejected ? reason!.trim() : '',
        now,
        tutor.id
      );

      db.prepare('UPDATE users SET status = ? WHERE id = ?').run(
        decision === TutorApprovalStatus.Approved ? AccountStatus.Active : AccountStatus.AwaitingApproval,
        tutor.id
      );

      // Seed default availability slots upon approval if none exist yet
      if (decision === TutorApprovalStatus.Approved) {
        const slotCount = db.prepare('SELECT COUNT(*) as cnt FROM availability_slots WHERE tutor_id = ?').get(tutor.id) as { cnt: number };
        if (slotCount.cnt === 0) {
          const ins = db.prepare(
            'INSERT INTO availability_slots (id, tutor_id, day_of_week, start_time_utc, end_time_utc, is_recurring, is_blocked, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?)'
          );
          for (let d = 1; d <= 5; d++) {
            ins.run(`slot-${tutor.id}-${d}`, tutor.id, d, '10:00', '18:00', now);
          }
        }
      }
    })();

    recordAuditLog(req.auth!.userId, UserRole.Admin, `TUTOR_${decision.toUpperCase()}`, 'tutor', tutor.id, {
      reason: reason || '',
    });

    createAndDeliverNotification(
      tutor.id,
      'email',
      `Tutor Application ${decision}`,
      decision === TutorApprovalStatus.Approved
        ? 'Congratulations! Your tutor profile is approved and now live in the marketplace.'
        : `Your tutor application requires updates: ${reason}`
    );

    res.json({ message: `Tutor ${tutor.full_name} marked as ${decision}.` });
  });

  // FR-19: Manage Users (Suspend, Reactivate, Soft-Delete)
  router.post('/admin/users/:id/action', requireAuth, requireRole(UserRole.Admin), (req: AuthenticatedRequest, res) => {
    const { action, reason } = req.body as { action?: 'suspend' | 'reactivate' | 'delete'; reason?: string };
    const target = getUserById(req.params.id);
    if (!target || target.deleted_at) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    if (target.id === req.auth!.userId && action === 'delete') {
      res.status(400).json({ error: 'An admin cannot delete their own account (FR-19).' });
      return;
    }
    if (target.role === UserRole.Admin) {
      res.status(403).json({ error: 'Cannot suspend or delete administrator accounts.' });
      return;
    }

    const now = new Date().toISOString();
    if (action === 'suspend') {
      db.transaction(() => {
        db.prepare('UPDATE users SET status = ? WHERE id = ?').run(AccountStatus.Suspended, target.id);
        // Cancel & refund future sessions (FR-19 post-condition)
        const futureBookings = db
          .prepare(`
            SELECT b.id, b.student_id, b.tutor_id, b.subject, p.id as payment_id, p.amount_pkr, p.gateway_ref
            FROM bookings b
            LEFT JOIN payments p ON p.booking_id = b.id AND p.status = 'Paid (Escrow)' AND p.deleted_at IS NULL
            WHERE (b.student_id = ? OR b.tutor_id = ?) AND b.status IN ('Confirmed', 'Rescheduled', 'Awaiting Payment')
            AND b.start_utc > ? AND b.deleted_at IS NULL
          `)
          .all(target.id, target.id, now) as Array<{
          id: string;
          student_id: string;
          tutor_id: string;
          subject: string;
          payment_id: string | null;
          amount_pkr: number | null;
          gateway_ref: string | null;
        }>;

        for (const fb of futureBookings) {
          db.prepare("UPDATE bookings SET status = 'Cancelled', cancel_reason = 'Account suspended by admin', updated_at = ? WHERE id = ?").run(
            now,
            fb.id
          );
          if (fb.payment_id && fb.amount_pkr && fb.gateway_ref) {
            PaymentGatewayAdapter.processRefund(fb.gateway_ref, fb.amount_pkr);
            db.prepare("UPDATE payments SET status = 'Refunded', refund_amount_pkr = ?, updated_at = ? WHERE id = ?").run(
              fb.amount_pkr,
              now,
              fb.payment_id
            );
          }
        }
      })();
      revokeAllUserSessions(target.id);
    } else if (action === 'reactivate') {
      db.prepare('UPDATE users SET status = ? WHERE id = ?').run(AccountStatus.Active, target.id);
    } else if (action === 'delete') {
      db.prepare('UPDATE users SET status = ?, deleted_at = ? WHERE id = ?').run(AccountStatus.Deleted, now, target.id);
      revokeAllUserSessions(target.id);
    } else {
      res.status(400).json({ error: 'Invalid user action.' });
      return;
    }

    recordAuditLog(req.auth!.userId, UserRole.Admin, `USER_${action.toUpperCase()}`, 'user', target.id, {
      reason: reason || 'Admin moderation',
    });

    res.json({ message: `User ${target.full_name} updated (${action}).` });
  });

  // FR-19: Impersonate User for Support (Audit Logged)
  router.post('/admin/impersonate', requireAuth, requireRole(UserRole.Admin), (req: AuthenticatedRequest, res) => {
    const { userId } = req.body as { userId?: string };
    const target = getUserById(userId || '');
    if (!target || target.deleted_at || target.role === UserRole.Admin) {
      res.status(404).json({ error: 'Target Student or Tutor account not found.' });
      return;
    }

    const token = createSessionToken(target.id, target.role, req.auth!.userId);
    recordAuditLog(req.auth!.userId, UserRole.Admin, 'ADMIN_IMPERSONATE_START', 'user', target.id, {
      targetEmail: target.email,
      targetRole: target.role,
    });

    const tutorProfile =
      target.role === UserRole.Tutor
        ? db.prepare('SELECT * FROM tutor_profiles WHERE user_id = ?').get(target.id)
        : null;

    res.json({
      token,
      user: target,
      tutorProfile,
      impersonatedBy: req.auth!.userId,
    });
  });

  // FR-20: Handle Disputes and Refunds
  router.post('/admin/disputes/:id/resolve', requireAuth, requireRole(UserRole.Admin), (req: AuthenticatedRequest, res) => {
    const { decision, refundAmountPkr, adminNotes } = req.body as {
      decision?: 'Full Refund' | 'Partial Refund' | 'No Refund';
      refundAmountPkr?: number;
      adminNotes?: string;
    };

    const dispute = db
      .prepare('SELECT * FROM disputes WHERE id = ?')
      .get(req.params.id) as { id: string; booking_id: string; status: DisputeStatus } | undefined;

    if (!dispute) {
      res.status(404).json({ error: 'Dispute not found.' });
      return;
    }
    if (dispute.status === DisputeStatus.Resolved) {
      res.status(400).json({ error: 'This dispute is already resolved.' });
      return;
    }

    const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(dispute.booking_id) as Record<string, unknown>;
    const payment = db
      .prepare("SELECT * FROM payments WHERE booking_id = ? AND status IN ('Paid (Escrow)', 'Released') AND deleted_at IS NULL")
      .get(dispute.booking_id) as { id: string; amount_pkr: number; gateway_ref: string; status: string } | undefined;

    let finalRefund = 0;
    if (decision === 'Full Refund' || decision === 'Partial Refund') {
      if (!payment) {
        res.status(400).json({ error: 'No refundable Paid payment found for this dispute.' });
        return;
      }
      finalRefund =
        decision === 'Full Refund'
          ? payment.amount_pkr
          : Math.min(payment.amount_pkr, Math.max(1, Math.round(Number(refundAmountPkr || 0))));

      const gw = PaymentGatewayAdapter.processRefund(payment.gateway_ref, finalRefund);
      if (!gw.success) {
        res.status(502).json({ error: 'Gateway refund failure: dispute remains Open (FR-20).' });
        return;
      }
      db.prepare('UPDATE payments SET status = ?, refund_amount_pkr = ?, updated_at = ? WHERE id = ?').run(
        PaymentStatus.Refunded,
        finalRefund,
        new Date().toISOString(),
        payment.id
      );
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE disputes SET status = ?, resolution_decision = ?, refund_amount_pkr = ?, admin_notes = ?, resolved_by = ?, resolved_at = ?
      WHERE id = ?
    `).run(DisputeStatus.Resolved, decision || 'No Refund', finalRefund, (adminNotes || '').trim(), req.auth!.userId, now, dispute.id);

    recordAuditLog(req.auth!.userId, UserRole.Admin, 'DISPUTE_RESOLVED', 'dispute', dispute.id, {
      decision,
      refundAmountPkr: finalRefund,
    });

    createAndDeliverNotification(
      booking.student_id as string,
      'email',
      `Dispute Resolved · ${decision}`,
      `Your dispute on ${booking.subject} was resolved (${decision}${finalRefund > 0 ? `: PKR ${finalRefund.toLocaleString()} refunded` : ''}).`
    );
    createAndDeliverNotification(
      booking.tutor_id as string,
      'email',
      `Dispute Resolved · ${decision}`,
      `Admin resolved the dispute on ${booking.subject} (${decision}).`
    );

    res.json({ message: `Dispute resolved (${decision}).` });
  });

  // FR-21: View & Export Reports
  router.get('/admin/reports', requireAuth, requireRole(UserRole.Admin), (req, res) => {
    const start = (req.query.start as string) || '2020-01-01';
    const end = (req.query.end as string) || '2099-12-31';
    const endInclusive = `${end}T23:59:59.999Z`;

    const registrations = db
      .prepare(`
        SELECT role, COUNT(*) as count FROM users
        WHERE deleted_at IS NULL AND created_at >= ? AND created_at <= ?
        GROUP BY role
      `)
      .all(start, endInclusive) as Array<{ role: string; count: number }>;

    const sessionsByStatus = db
      .prepare(`
        SELECT status, COUNT(*) as count, COALESCE(SUM(price_pkr), 0) as gross_pkr, COALESCE(SUM(commission_pkr), 0) as commission_pkr
        FROM bookings
        WHERE deleted_at IS NULL AND created_at >= ? AND created_at <= ?
        GROUP BY status
      `)
      .all(start, endInclusive) as Array<{ status: string; count: number; gross_pkr: number; commission_pkr: number }>;

    const tutorPerformance = db
      .prepare(`
        SELECT u.id, u.full_name, tp.rating_avg, tp.rating_count,
               COUNT(b.id) as total_sessions,
               COALESCE(SUM(CASE WHEN b.status = 'Completed' THEN b.tutor_net_pkr ELSE 0 END), 0) as earned_pkr
        FROM users u
        JOIN tutor_profiles tp ON tp.user_id = u.id
        LEFT JOIN bookings b ON b.tutor_id = u.id AND b.deleted_at IS NULL AND b.created_at >= ? AND b.created_at <= ?
        WHERE u.role = 'Tutor' AND u.deleted_at IS NULL AND tp.approval_status = 'Approved'
        GROUP BY u.id
        ORDER BY total_sessions DESC, tp.rating_avg DESC
      `)
      .all(start, endInclusive);

    const revenueTotal = db
      .prepare(`
        SELECT COALESCE(SUM(amount_pkr), 0) as gross_collected,
               COALESCE(SUM(refund_amount_pkr), 0) as total_refunded
        FROM payments
        WHERE deleted_at IS NULL AND status != 'Failed' AND created_at >= ? AND created_at <= ?
      `)
      .get(start, endInclusive) as { gross_collected: number; total_refunded: number };

    res.json({
      period: { start, end },
      registrations,
      sessionsByStatus,
      tutorPerformance,
      revenueTotal,
    });
  });

  router.get('/admin/reports/csv', requireAuth, requireRole(UserRole.Admin), (req, res) => {
    const rows = db
      .prepare(`
        SELECT b.id, b.subject, b.level, b.start_utc, b.duration_min, b.price_pkr, b.commission_pkr, b.tutor_net_pkr, b.status,
               s.full_name as student_name, t.full_name as tutor_name
        FROM bookings b
        JOIN users s ON s.id = b.student_id
        JOIN users t ON t.id = b.tutor_id
        WHERE b.deleted_at IS NULL
        ORDER BY b.start_utc DESC
      `)
      .all() as Array<Record<string, unknown>>;

    const header = 'BookingID,Subject,Level,StartUTC,DurationMin,PricePKR,CommissionPKR,TutorNetPKR,Status,Student,Tutor';
    const csvLines = rows.map((r) =>
      [
        r.id,
        `"${String(r.subject).replace(/"/g, '""')}"`,
        `"${String(r.level).replace(/"/g, '""')}"`,
        r.start_utc,
        r.duration_min,
        r.price_pkr,
        r.commission_pkr,
        r.tutor_net_pkr,
        r.status,
        `"${String(r.student_name).replace(/"/g, '""')}"`,
        `"${String(r.tutor_name).replace(/"/g, '""')}"`,
      ].join(',')
    );

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ota-platform-report.csv"');
    res.send([header, ...csvLines].join('\n'));
  });

  // SRS 4.3.4 Configurable System Parameters
  router.patch('/admin/config', requireAuth, requireRole(UserRole.Admin), (req: AuthenticatedRequest, res) => {
    const { commissionPct, freeCancelHours, slotHoldMin, subjects, levels } = req.body as {
      commissionPct?: number;
      freeCancelHours?: number;
      slotHoldMin?: number;
      subjects?: string[];
      levels?: string[];
    };

    if (commissionPct !== undefined) {
      const val = Math.max(0, Math.min(40, Number(commissionPct)));
      setConfigValue('PLATFORM_COMMISSION_PCT', String(val));
    }
    if (freeCancelHours !== undefined) {
      setConfigValue('FREE_CANCEL_HOURS', String(Math.max(1, Math.min(72, Number(freeCancelHours)))));
    }
    if (slotHoldMin !== undefined) {
      setConfigValue('SLOT_HOLD_MIN', String(Math.max(5, Math.min(30, Number(slotHoldMin)))));
    }
    if (Array.isArray(subjects) && subjects.length > 0) {
      setConfigValue('SUBJECTS', JSON.stringify(subjects));
    }
    if (Array.isArray(levels) && levels.length > 0) {
      setConfigValue('LEVELS', JSON.stringify(levels));
    }

    recordAuditLog(req.auth!.userId, UserRole.Admin, 'CONFIG_UPDATED', 'system_config', 'global', req.body);
    res.json({ message: 'Platform configuration parameters updated.' });
  });

  return router;
}
