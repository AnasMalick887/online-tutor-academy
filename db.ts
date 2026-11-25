import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { hashPassword } from './auth.ts';
import {
  AccountStatus,
  AssignmentStatus,
  BookingStatus,
  DEFAULT_LANGUAGES,
  DEFAULT_LEVELS,
  DEFAULT_SUBJECTS,
  DisputeStatus,
  PaymentStatus,
  SRS_CONSTANTS,
  TutorApprovalStatus,
  UserRole,
} from '../src/shared/srsConstants.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'ota_academy.db');
export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initDatabase(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS system_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_credentials (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_hash TEXT NOT NULL,
      claimed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      status TEXT NOT NULL,
      dob TEXT,
      guardian_email TEXT,
      timezone TEXT NOT NULL DEFAULT 'Asia/Karachi',
      bio TEXT DEFAULT '',
      avatar_color TEXT NOT NULL DEFAULT '#1D4ED8',
      failed_login_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      created_at TEXT NOT NULL,
      deleted_at TEXT
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      purpose TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS tutor_profiles (
      user_id TEXT PRIMARY KEY,
      headline TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '',
      qualifications TEXT NOT NULL DEFAULT '',
      experience_years INTEGER NOT NULL DEFAULT 1,
      hourly_rate_pkr INTEGER NOT NULL DEFAULT 1500,
      subjects_json TEXT NOT NULL DEFAULT '[]',
      levels_json TEXT NOT NULL DEFAULT '[]',
      languages_json TEXT NOT NULL DEFAULT '["English"]',
      intro_video_url TEXT DEFAULT '',
      documents_json TEXT NOT NULL DEFAULT '[]',
      approval_status TEXT NOT NULL DEFAULT 'Pending',
      rejection_reason TEXT DEFAULT '',
      rating_avg REAL NOT NULL DEFAULT 0,
      rating_count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS availability_slots (
      id TEXT PRIMARY KEY,
      tutor_id TEXT NOT NULL,
      day_of_week INTEGER NOT NULL,
      start_time_utc TEXT NOT NULL,
      end_time_utc TEXT NOT NULL,
      is_recurring INTEGER NOT NULL DEFAULT 1,
      specific_date TEXT,
      is_blocked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (tutor_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id TEXT PRIMARY KEY,
      student_id TEXT NOT NULL,
      tutor_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      level TEXT NOT NULL,
      start_utc TEXT NOT NULL,
      end_utc TEXT NOT NULL,
      duration_min INTEGER NOT NULL,
      note TEXT DEFAULT '',
      price_pkr INTEGER NOT NULL,
      commission_pkr INTEGER NOT NULL,
      tutor_net_pkr INTEGER NOT NULL,
      status TEXT NOT NULL,
      hold_expires_at TEXT,
      cancel_reason TEXT DEFAULT '',
      cancelled_by TEXT,
      room_token TEXT,
      whiteboard_json TEXT DEFAULT '[]',
      attendance_json TEXT DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      FOREIGN KEY (student_id) REFERENCES users(id),
      FOREIGN KEY (tutor_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      booking_id TEXT NOT NULL,
      student_id TEXT NOT NULL,
      amount_pkr INTEGER NOT NULL,
      method TEXT NOT NULL,
      gateway_ref TEXT NOT NULL,
      card_last4 TEXT NOT NULL,
      status TEXT NOT NULL,
      refund_amount_pkr INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      FOREIGN KEY (booking_id) REFERENCES bookings(id),
      FOREIGN KEY (student_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS study_materials (
      id TEXT PRIMARY KEY,
      tutor_id TEXT NOT NULL,
      student_id TEXT,
      booking_id TEXT,
      title TEXT NOT NULL,
      url_or_name TEXT NOT NULL,
      file_type TEXT NOT NULL,
      size_kb INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (tutor_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS assignments (
      id TEXT PRIMARY KEY,
      tutor_id TEXT NOT NULL,
      student_id TEXT NOT NULL,
      booking_id TEXT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      due_at TEXT NOT NULL,
      allow_late INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      submission_text TEXT DEFAULT '',
      submission_file TEXT DEFAULT '',
      submitted_at TEXT,
      score INTEGER,
      feedback TEXT DEFAULT '',
      graded_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (tutor_id) REFERENCES users(id),
      FOREIGN KEY (student_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id TEXT PRIMARY KEY,
      booking_id TEXT NOT NULL UNIQUE,
      tutor_id TEXT NOT NULL,
      student_id TEXT NOT NULL,
      rating INTEGER NOT NULL,
      comment TEXT DEFAULT '',
      tutor_reply TEXT DEFAULT '',
      tutor_replied_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (booking_id) REFERENCES bookings(id),
      FOREIGN KEY (tutor_id) REFERENCES users(id),
      FOREIGN KEY (student_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      booking_id TEXT,
      body TEXT NOT NULL,
      attachment_name TEXT DEFAULT '',
      attachment_size_kb INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (sender_id) REFERENCES users(id),
      FOREIGN KEY (recipient_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS classroom_events (
      id TEXT PRIMARY KEY,
      booking_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (booking_id) REFERENCES bookings(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      delivery_status TEXT NOT NULL,
      retry_count INTEGER NOT NULL DEFAULT 0,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS disputes (
      id TEXT PRIMARY KEY,
      booking_id TEXT NOT NULL,
      reporter_id TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'Session Quality',
      reason TEXT NOT NULL,
      status TEXT NOT NULL,
      resolution_decision TEXT DEFAULT '',
      refund_amount_pkr INTEGER NOT NULL DEFAULT 0,
      admin_notes TEXT DEFAULT '',
      resolved_by TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT,
      FOREIGN KEY (booking_id) REFERENCES bookings(id),
      FOREIGN KEY (reporter_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS payouts (
      id TEXT PRIMARY KEY,
      tutor_id TEXT NOT NULL,
      amount_pkr INTEGER NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (tutor_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  seedInitialData();
}

export function getConfigValue(key: string, fallback: string): string {
  const row = db.prepare('SELECT value FROM system_config WHERE key = ?').get(key) as { value: string } | undefined;
  return row ? row.value : fallback;
}

export function setConfigValue(key: string, value: string): void {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `).run(key, value, now);
}

export function recordAuditLog(
  actorId: string,
  actorRole: string,
  action: string,
  targetType: string,
  targetId: string,
  details: Record<string, unknown> = {}
): void {
  db.prepare(`
    INSERT INTO audit_logs (id, actor_id, actor_role, action, target_type, target_id, details_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    `aud-${crypto.randomBytes(6).toString('hex')}`,
    actorId,
    actorRole,
    action,
    targetType,
    targetId,
    JSON.stringify(details),
    new Date().toISOString()
  );
}

function seedInitialData(): void {
  const now = new Date();
  const isoNow = now.toISOString();

  // Seed default configuration parameters (SRS 4.3.4 & Appendix A)
  const existingConfig = db.prepare('SELECT COUNT(*) as cnt FROM system_config').get() as { cnt: number };
  if (existingConfig.cnt === 0) {
    setConfigValue('PLATFORM_COMMISSION_PCT', '15');
    setConfigValue('FREE_CANCEL_HOURS', String(SRS_CONSTANTS.FREE_CANCEL_HOURS));
    setConfigValue('SLOT_HOLD_MIN', String(SRS_CONSTANTS.SLOT_HOLD_MIN));
    setConfigValue('PAYOUT_DELAY_HR', String(SRS_CONSTANTS.PAYOUT_DELAY_HR));
    setConfigValue('SUBJECTS', JSON.stringify(DEFAULT_SUBJECTS));
    setConfigValue('LEVELS', JSON.stringify(DEFAULT_LEVELS));
    setConfigValue('LANGUAGES', JSON.stringify(DEFAULT_LANGUAGES));
  }

  const userCount = db.prepare('SELECT COUNT(*) as cnt FROM users').get() as { cnt: number };
  if (userCount.cnt > 0) return;

  // Placeholder unreachable random hash for admin user row; actual admin login checks ADMIN_PASSCODE or admin_credentials table
  const adminRowHash = hashPassword(crypto.randomBytes(24).toString('hex'));
  const demoStudentHash = hashPassword('StudentPass1');
  const demoTutorHash = hashPassword('TutorPass1');

  const insertUser = db.prepare(`
    INSERT INTO users (id, full_name, email, password_hash, role, status, dob, guardian_email, timezone, bio, avatar_color, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Admin account row (used as actor identity when logged in via admin-claim / ADMIN_PASSCODE)
  insertUser.run(
    'admin-1',
    'Academy Administrator',
    'admin@ota.edu.pk',
    adminRowHash,
    UserRole.Admin,
    AccountStatus.Active,
    '1990-01-15',
    null,
    'Asia/Karachi',
    'Platform Operations & Academic Quality Lead',
    '#0F172A',
    isoNow
  );

  // Students
  insertUser.run(
    'student-1',
    'Ayesha Tariq',
    'ayesha.student@ota.edu.pk',
    demoStudentHash,
    UserRole.Student,
    AccountStatus.Active,
    '2004-05-12',
    null,
    'Asia/Karachi',
    'Computer Science undergraduate preparing for algorithms and calculus.',
    '#1D4ED8',
    isoNow
  );
  insertUser.run(
    'student-2',
    'Hamza Siddiqui',
    'hamza.student@ota.edu.pk',
    demoStudentHash,
    UserRole.Student,
    AccountStatus.Active,
    '2011-08-20',
    'tariq.parent@ota.edu.pk',
    'Asia/Karachi',
    'O-Level student focusing on Mathematics and Physics.',
    '#0369A1',
    isoNow
  );
  insertUser.run(
    'student-3',
    'Zainab Farooq',
    'zainab.student@ota.edu.pk',
    demoStudentHash,
    UserRole.Student,
    AccountStatus.Active,
    '2006-03-04',
    null,
    'Asia/Karachi',
    'A-Level Pre-Engineering candidate.',
    '#047857',
    isoNow
  );

  // Tutors (6 Approved + 1 Pending for Admin FR-18 queue)
  const tutors = [
    {
      id: 'tutor-1',
      name: 'Dr. Kamran Qureshi',
      email: 'dr.kamran@ota.edu.pk',
      color: '#1E3A8A',
      headline: 'PhD Mathematics · Former Olympiad Coach & Calculus Specialist',
      bio: 'With 11 years of university and Cambridge A-Level teaching experience, I break down multivariable calculus, linear algebra, and differential equations using live interactive proofs on the whiteboard.',
      qualifications: 'PhD Applied Mathematics (NED University), MSc Mathematics',
      experience: 11,
      rate: 2800,
      subjects: ['Mathematics', 'Physics'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate', 'Undergraduate'],
      languages: ['English', 'Urdu'],
      docs: ['PhD_Degree_Verified.pdf', 'NED_Faculty_Certificate.pdf'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 4.9,
      ratingCount: 2,
    },
    {
      id: 'tutor-2',
      name: 'Engr. Sara Mansoor',
      email: 'sara.mansoor@ota.edu.pk',
      color: '#0F766E',
      headline: 'Senior Software Architect · Data Structures, Python & Web Systems',
      bio: 'Software engineering lead teaching O/A-Level Computer Science (9618), C++, Python, algorithms, and full-stack architecture through live code walkthroughs and structured assignments.',
      qualifications: 'BE Computer & Information Systems, AWS Certified Solutions Architect',
      experience: 8,
      rate: 2500,
      subjects: ['Computer Science', 'Mathematics'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate', 'Undergraduate', 'Adult & Professional'],
      languages: ['English', 'Urdu'],
      docs: ['BE_CIS_Transcript.pdf', 'Industry_Experience_Letter.jpg'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 4.8,
      ratingCount: 1,
    },
    {
      id: 'tutor-3',
      name: 'Prof. Bilal Ahmed',
      email: 'bilal.physics@ota.edu.pk',
      color: '#4338CA',
      headline: 'MPhil Physics · Cambridge O & A-Level Mechanics & Electromagnetism',
      bio: 'Specializing in conceptual physics and past-paper mastery. Every session combines visual free-body diagrams on the shared whiteboard with timed exam drills.',
      qualifications: 'MPhil Physics (University of Karachi), Cambridge Certified Examiner',
      experience: 9,
      rate: 2200,
      subjects: ['Physics', 'Chemistry'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate'],
      languages: ['English', 'Urdu'],
      docs: ['MPhil_Physics_Degree.pdf'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 4.7,
      ratingCount: 1,
    },
    {
      id: 'tutor-4',
      name: 'Dr. Mahnoor Javed',
      email: 'mahnoor.chem@ota.edu.pk',
      color: '#B45309',
      headline: 'Organic Chemistry & Pre-Med Biology Mentor',
      bio: 'Helping medical-track and A-Level students master reaction mechanisms, stoichiometry, and cellular biology with clear study notes and weekly graded quizzes.',
      qualifications: 'MBBS, MSc Biochemistry',
      experience: 6,
      rate: 2000,
      subjects: ['Chemistry', 'Biology'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate', 'Undergraduate'],
      languages: ['English', 'Urdu'],
      docs: ['Medical_Degree_Verified.pdf'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 4.9,
      ratingCount: 1,
    },
    {
      id: 'tutor-5',
      name: 'Hira Rehman',
      email: 'hira.english@ota.edu.pk',
      color: '#7C2D12',
      headline: 'MA English Literature · Academic Writing, IELTS & Critical Analysis',
      bio: 'Structured essay coaching, literary criticism, and IELTS band 8+ preparation with line-by-line feedback on every written assignment.',
      qualifications: 'MA English Literature, CELTA Certified',
      experience: 7,
      rate: 1800,
      subjects: ['English Literature'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate', 'Adult & Professional'],
      languages: ['English', 'Urdu'],
      docs: ['CELTA_Certificate.pdf', 'MA_Literature.pdf'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 4.6,
      ratingCount: 1,
    },
    {
      id: 'tutor-6',
      name: 'Usman Raza, CFA',
      email: 'usman.finance@ota.edu.pk',
      color: '#1E293B',
      headline: 'CFA Charterholder · Economics, Accounting & Financial Modeling',
      bio: 'Practical macroeconomics, ACCA/CA foundational accounting, and corporate finance taught with real-world balance sheets and case studies.',
      qualifications: 'CFA Charterholder, BS Accounting & Finance',
      experience: 10,
      rate: 3200,
      subjects: ['Economics', 'Accounting & Finance'],
      levels: ['A-Level / Intermediate', 'Undergraduate', 'Adult & Professional'],
      languages: ['English', 'Urdu'],
      docs: ['CFA_Charter_Verification.pdf'],
      approval: TutorApprovalStatus.Approved,
      ratingAvg: 5.0,
      ratingCount: 1,
    },
    {
      id: 'tutor-pending-7',
      name: 'Fariha Naeem',
      email: 'fariha.applicant@ota.edu.pk',
      color: '#334155',
      headline: 'MSc Data Science · Applied Statistics & Python Tutoring',
      bio: 'Graduate teaching assistant applying to teach undergraduate statistics, probability, and introductory Python programming.',
      qualifications: 'MSc Data Science (LUMS)',
      experience: 3,
      rate: 1900,
      subjects: ['Computer Science', 'Mathematics'],
      levels: ['O-Level / Matric', 'A-Level / Intermediate', 'Undergraduate'],
      languages: ['English', 'Urdu'],
      docs: ['LUMS_MSc_Degree.pdf', 'CNIC_Identity_Check.jpg'],
      approval: TutorApprovalStatus.Pending,
      ratingAvg: 0,
      ratingCount: 0,
    },
  ];

  const insertTutorProfile = db.prepare(`
    INSERT INTO tutor_profiles (
      user_id, headline, bio, qualifications, experience_years, hourly_rate_pkr,
      subjects_json, levels_json, languages_json, intro_video_url, documents_json,
      approval_status, rating_avg, rating_count, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertSlot = db.prepare(`
    INSERT INTO availability_slots (id, tutor_id, day_of_week, start_time_utc, end_time_utc, is_recurring, specific_date, is_blocked, created_at)
    VALUES (?, ?, ?, ?, ?, 1, NULL, 0, ?)
  `);

  for (const t of tutors) {
    insertUser.run(
      t.id,
      t.name,
      t.email,
      demoTutorHash,
      UserRole.Tutor,
      t.approval === TutorApprovalStatus.Approved ? AccountStatus.Active : AccountStatus.AwaitingApproval,
      '1989-07-10',
      null,
      'Asia/Karachi',
      t.bio,
      t.color,
      isoNow
    );
    insertTutorProfile.run(
      t.id,
      t.headline,
      t.bio,
      t.qualifications,
      t.experience,
      t.rate,
      JSON.stringify(t.subjects),
      JSON.stringify(t.levels),
      JSON.stringify(t.languages),
      'https://example.org/intro-session-preview',
      JSON.stringify(t.docs),
      t.approval,
      t.ratingAvg,
      t.ratingCount,
      isoNow
    );

    if (t.approval === TutorApprovalStatus.Approved) {
      // Create weekly slots across days 0..6 in UTC so every day has bookable slots
      for (let day = 0; day <= 6; day++) {
        insertSlot.run(`slot-${t.id}-${day}-am`, t.id, day, '09:00', '13:00', isoNow);
        insertSlot.run(`slot-${t.id}-${day}-pm`, t.id, day, '14:00', '19:00', isoNow);
      }
    }
  }

  // Seed sample Bookings (including one starting RIGHT NOW / in 2 mins so Live Classroom is immediately joinable!)
  const in2Min = new Date(now.getTime() + 2 * 60 * 1000);
  const in62Min = new Date(in2Min.getTime() + 60 * 60 * 1000);
  const in3Days = new Date(now.getTime() + 72 * 60 * 60 * 1000);
  const in3DaysEnd = new Date(in3Days.getTime() + 60 * 60 * 1000);
  const past4Days = new Date(now.getTime() - 96 * 60 * 60 * 1000);
  const past4DaysEnd = new Date(past4Days.getTime() + 60 * 60 * 1000);
  const past1Day = new Date(now.getTime() - 28 * 60 * 60 * 1000);
  const past1DayEnd = new Date(past1Day.getTime() + 60 * 60 * 1000);

  const insertBooking = db.prepare(`
    INSERT INTO bookings (
      id, student_id, tutor_id, subject, level, start_utc, end_utc, duration_min,
      note, price_pkr, commission_pkr, tutor_net_pkr, status, room_token, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertPayment = db.prepare(`
    INSERT INTO payments (id, booking_id, student_id, amount_pkr, method, gateway_ref, card_last4, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Booking 1: Live / Joinable right now (Ayesha + Dr. Kamran)
  insertBooking.run(
    'bk-live-1',
    'student-1',
    'tutor-1',
    'Mathematics',
    'Undergraduate',
    in2Min.toISOString(),
    in62Min.toISOString(),
    60,
    'Reviewing Eigenvalues & Laplace Transforms before midterms.',
    2800,
    420,
    2380,
    BookingStatus.Confirmed,
    null,
    isoNow,
    isoNow
  );
  insertPayment.run('pay-1', 'bk-live-1', 'student-1', 2800, 'card', 'OTA-PAY-SEED01', '4242', PaymentStatus.Paid, isoNow, isoNow);

  // Booking 2: Upcoming in 3 days (Ayesha + Engr. Sara)
  insertBooking.run(
    'bk-up-2',
    'student-1',
    'tutor-2',
    'Computer Science',
    'Undergraduate',
    in3Days.toISOString(),
    in3DaysEnd.toISOString(),
    60,
    'Graph traversal (BFS/DFS) and dynamic programming practice.',
    2500,
    375,
    2125,
    BookingStatus.Confirmed,
    null,
    isoNow,
    isoNow
  );
  insertPayment.run('pay-2', 'bk-up-2', 'student-1', 2500, 'jazzcash', 'OTA-PAY-SEED02', '8819', PaymentStatus.Paid, isoNow, isoNow);

  // Booking 3: Completed 4 days ago, already reviewed & payment released (Ayesha + Dr. Kamran)
  insertBooking.run(
    'bk-done-3',
    'student-1',
    'tutor-1',
    'Mathematics',
    'Undergraduate',
    past4Days.toISOString(),
    past4DaysEnd.toISOString(),
    60,
    'Multivariable Partial Derivatives.',
    2800,
    420,
    2380,
    BookingStatus.Completed,
    null,
    past4Days.toISOString(),
    past4DaysEnd.toISOString()
  );
  insertPayment.run('pay-3', 'bk-done-3', 'student-1', 2800, 'card', 'OTA-PAY-SEED03', '4242', PaymentStatus.Released, past4Days.toISOString(), isoNow);

  // Booking 4: Completed 28 hours ago, NOT yet reviewed by student + has an Open Dispute for Admin Console demo (Hamza + Prof. Bilal)
  insertBooking.run(
    'bk-done-4',
    'student-2',
    'tutor-3',
    'Physics',
    'O-Level / Matric',
    past1Day.toISOString(),
    past1DayEnd.toISOString(),
    60,
    'Electromagnetic Induction Past Papers.',
    2200,
    330,
    1870,
    BookingStatus.Completed,
    null,
    past1Day.toISOString(),
    past1DayEnd.toISOString()
  );
  insertPayment.run('pay-4', 'bk-done-4', 'student-2', 2200, 'easypaisa', 'OTA-PAY-SEED04', '3301', PaymentStatus.Paid, past1Day.toISOString(), past1Day.toISOString());

  // Seed Reviews
  const insertReview = db.prepare(`
    INSERT INTO reviews (id, booking_id, tutor_id, student_id, rating, comment, tutor_reply, tutor_replied_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertReview.run(
    'rev-1',
    'bk-done-3',
    'tutor-1',
    'student-1',
    5,
    'Dr. Kamran explained partial derivatives clearly on the whiteboard and shared practice sheets right after class.',
    'Thank you Ayesha! Keep practicing the chain rule exercises before our next session.',
    isoNow,
    past4DaysEnd.toISOString()
  );

  // Seed Study Materials (FR-13)
  const insertMat = db.prepare(`
    INSERT INTO study_materials (id, tutor_id, student_id, booking_id, title, url_or_name, file_type, size_kb, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertMat.run(
    'mat-1',
    'tutor-1',
    'student-1',
    'bk-done-3',
    'Multivariable Calculus Formula Sheet & Solved Examples',
    'Calculus_Partial_Derivatives_Notes.pdf',
    'PDF',
    1420,
    past4DaysEnd.toISOString()
  );
  insertMat.run(
    'mat-2',
    'tutor-2',
    'student-1',
    'bk-up-2',
    'Graph Algorithms Visual Reference Slides',
    'https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/',
    'URL',
    0,
    isoNow
  );

  // Seed Assignments (FR-14, FR-15)
  const dueIn2Days = new Date(now.getTime() + 48 * 60 * 60 * 1000).toISOString();
  const insertAssign = db.prepare(`
    INSERT INTO assignments (id, tutor_id, student_id, booking_id, title, description, due_at, allow_late, status, submission_text, submission_file, submitted_at, score, feedback, graded_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertAssign.run(
    'asg-1',
    'tutor-1',
    'student-1',
    'bk-live-1',
    'Problem Set 2: Laplace Transforms & Initial Value Problems',
    'Solve problems 1 through 5 showing full partial fraction decomposition steps. Upload your solution summary or attach your PDF.',
    dueIn2Days,
    1,
    AssignmentStatus.Published,
    '',
    '',
    null,
    null,
    '',
    null,
    isoNow
  );
  insertAssign.run(
    'asg-2',
    'tutor-1',
    'student-1',
    'bk-done-3',
    'Problem Set 1: Directional Derivatives & Gradients',
    'Compute the gradient vector and directional derivative at P(1, -2, 3).',
    past1Day.toISOString(),
    0,
    AssignmentStatus.Graded,
    'Computed grad f(x,y,z) = (2x, -4y, 6z) and unit vector projection.',
    'Ayesha_PS1_Solutions.pdf',
    past1Day.toISOString(),
    94,
    'Excellent step-by-step normalization of the direction vector. Minor sign check needed in Q3b.',
    isoNow,
    past4Days.toISOString()
  );
  insertAssign.run(
    'asg-3',
    'tutor-2',
    'student-1',
    'bk-up-2',
    'Lab 1: Implement BFS Shortest Path in Python',
    'Write an adjacency-list BFS function returning shortest hop distance between two nodes.',
    dueIn2Days,
    1,
    AssignmentStatus.Submitted,
    'def bfs_shortest(graph, start, goal): queue = deque([(start, 0)]); visited = {start} ...',
    'bfs_shortest.py',
    isoNow,
    null,
    '',
    null,
    past1Day.toISOString()
  );

  // Seed Messages (internal platform-only messaging)
  const insertMsg = db.prepare(`
    INSERT INTO messages (id, sender_id, recipient_id, booking_id, body, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertMsg.run(
    'msg-1',
    'tutor-1',
    'student-1',
    'bk-live-1',
    'Hi Ayesha, I uploaded the Laplace Transform problem set to your dashboard. We will work through #3 live on the whiteboard today.',
    isoNow
  );
  insertMsg.run(
    'msg-2',
    'student-1',
    'tutor-1',
    'bk-live-1',
    'Thank you Dr. Kamran! I have reviewed the notes and will join the classroom 5 minutes early.',
    isoNow
  );

  // Seed Notifications (FR-17)
  const insertNotif = db.prepare(`
    INSERT INTO notifications (id, user_id, channel, title, body, delivery_status, retry_count, is_read, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
  `);
  insertNotif.run(
    'notif-1',
    'student-1',
    'in_app',
    'Session Reminder (Starting Soon)',
    'Your Mathematics session with Dr. Kamran Qureshi is open for check-in.',
    'Delivered (In-App)',
    isoNow
  );
  insertNotif.run(
    'notif-2',
    'student-1',
    'email',
    'Assignment Graded: 94/100',
    'Dr. Kamran Qureshi graded Problem Set 1 with score 94/100.',
    'Delivered via EMAIL to ayesha.student@ota.edu.pk',
    isoNow
  );
  insertNotif.run(
    'notif-3',
    'tutor-1',
    'in_app',
    'New Assignment Submission',
    'Ayesha Tariq is enrolled in your upcoming Mathematics session.',
    'Delivered (In-App)',
    isoNow
  );

  // Seed 1 Open Dispute for Admin Console (FR-20)
  db.prepare(`
    INSERT INTO disputes (id, booking_id, reporter_id, category, reason, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    'disp-1',
    'bk-done-4',
    'student-2',
    'Audio / Connection Issue',
    'Tutor audio dropped for the last 20 minutes of the Physics session; requesting partial refund of PKR 800.',
    DisputeStatus.Open,
    isoNow
  );

  // Seed Classroom chat/attendance transcript for bk-done-4 so Admin Dispute review is rich
  db.prepare(`
    INSERT INTO classroom_events (id, booking_id, user_id, event_type, payload_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    'evt-seed-1',
    'bk-done-4',
    'student-2',
    'chat',
    JSON.stringify({ senderName: 'Hamza Siddiqui', text: 'Sir, your microphone audio cut out during Question 4.' }),
    past1DayEnd.toISOString()
  );
  db.prepare(`
    INSERT INTO classroom_events (id, booking_id, user_id, event_type, payload_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    'evt-seed-2',
    'bk-done-4',
    'tutor-3',
    'chat',
    JSON.stringify({ senderName: 'Prof. Bilal Ahmed', text: 'Apologies Hamza, my ISP had a packet drop. I have shared the full worked PDF notes.' }),
    past1DayEnd.toISOString()
  );

  recordAuditLog('system', 'Admin', 'SYSTEM_SEEDED', 'system', 'ota_v1', {
    tutorsSeeded: tutors.length,
    studentsSeeded: 3,
  });
}
