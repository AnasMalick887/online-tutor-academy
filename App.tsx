import React, { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import {
  apiRequest,
  getAuthToken,
  popAdminTokenFromImpersonation,
  saveAdminTokenForImpersonation,
  setAuthToken,
} from './lib/api.ts';
import { DEFAULT_LANGUAGES, DEFAULT_LEVELS, DEFAULT_SUBJECTS, SRS_CONSTANTS, UserRole } from './shared/srsConstants.ts';
import type { SystemConfig, TutorCard, TutorProfileRaw, User } from './types/ota.ts';
import { Navbar, type AppRoute } from './components/Navbar.tsx';
import { Footer } from './components/Footer.tsx';
import { HomeView } from './components/HomeView.tsx';
import { AuthView } from './components/AuthView.tsx';
import { TutorSearchView } from './components/TutorSearchView.tsx';
import { TutorProfileView } from './components/TutorProfileView.tsx';
import { StudentDashboard } from './components/StudentDashboard.tsx';
import { TutorDashboard } from './components/TutorDashboard.tsx';
import { LiveClassroomView } from './components/LiveClassroomView.tsx';
import { MessagesAndNotificationsView } from './components/MessagesAndNotificationsView.tsx';
import { AdminConsoleView } from './components/AdminConsoleView.tsx';
import { HelpCentreView } from './components/HelpCentreView.tsx';

const FALLBACK_CONFIG: SystemConfig = {
  commissionPct: 15,
  freeCancelHours: SRS_CONSTANTS.FREE_CANCEL_HOURS,
  slotHoldMin: SRS_CONSTANTS.SLOT_HOLD_MIN,
  payoutDelayHr: SRS_CONSTANTS.PAYOUT_DELAY_HR,
  subjects: DEFAULT_SUBJECTS,
  levels: DEFAULT_LEVELS,
  languages: DEFAULT_LANGUAGES,
};

export default function App() {
  const [route, setRoute] = useState<AppRoute>('home');
  const [authTab, setAuthTab] = useState<'login' | 'register' | 'admin'>('login');
  const [config, setConfig] = useState<SystemConfig>(FALLBACK_CONFIG);
  const [featuredTutors, setFeaturedTutors] = useState<TutorCard[]>([]);
  const [searchFilters, setSearchFilters] = useState({ q: '', subject: '', level: '' });
  const [selectedTutorId, setSelectedTutorId] = useState<string>('');
  const [activeClassroomBookingId, setActiveClassroomBookingId] = useState<string>('');

  const [user, setUser] = useState<User | null>(null);
  const [tutorProfile, setTutorProfile] = useState<TutorProfileRaw | null>(null);
  const [impersonatedBy, setImpersonatedBy] = useState<string | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [legalModal, setLegalModal] = useState<'terms' | 'privacy' | 'refund' | 'contact' | null>(null);

  const notifWsRef = useRef<WebSocket | null>(null);

  const loadConfigAndFeatured = async () => {
    try {
      const [cfg, tutRes] = await Promise.all([
        apiRequest<SystemConfig>('/config'),
        apiRequest<{ tutors: TutorCard[] }>('/tutors?limit=6&sort=rating'),
      ]);
      setConfig(cfg);
      setFeaturedTutors(tutRes.tutors);
    } catch {
      // keep defaults
    }
  };

  useEffect(() => {
    loadConfigAndFeatured();
  }, []);

  const refreshUnreadNotifications = async () => {
    if (!getAuthToken()) return;
    try {
      const res = await apiRequest<{ notifications: Array<{ is_read: number }> }>('/notifications');
      setUnreadCount(res.notifications.filter((n) => !n.is_read).length);
    } catch {
      // ignore
    }
  };

  // Connect lightweight notification WebSocket whenever user logs in
  useEffect(() => {
    if (!user) {
      notifWsRef.current?.close();
      notifWsRef.current = null;
      setUnreadCount(0);
      return;
    }
    refreshUnreadNotifications();
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    notifWsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'auth', token: getAuthToken() }));
    };
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'notification') {
          setUnreadCount((c) => c + 1);
        }
      } catch {
        // ignore
      }
    };
    return () => ws.close();
  }, [user]);

  const handleAuthenticated = (token: string, authedUser: User, tProfile?: TutorProfileRaw | null) => {
    setAuthToken(token);
    setUser(authedUser);
    setTutorProfile(tProfile || null);
    setImpersonatedBy(null);
    if (authedUser.role === UserRole.Admin) {
      setRoute('admin');
    } else {
      setRoute('dashboard');
    }
  };

  const handleLogout = async () => {
    try {
      if (getAuthToken()) {
        await apiRequest('/auth/logout', { method: 'POST' });
      }
    } catch {
      // ignore
    } finally {
      setAuthToken(null);
      setUser(null);
      setTutorProfile(null);
      setImpersonatedBy(null);
      setRoute('home');
    }
  };

  const handleImpersonated = (
    impersonatedToken: string,
    targetUser: User,
    tProfile: TutorProfileRaw | null,
    adminId: string
  ) => {
    const currentAdminToken = getAuthToken();
    if (currentAdminToken) {
      saveAdminTokenForImpersonation(currentAdminToken);
    }
    setAuthToken(impersonatedToken);
    setUser(targetUser);
    setTutorProfile(tProfile);
    setImpersonatedBy(adminId);
    setRoute('dashboard');
  };

  const handleExitImpersonation = async () => {
    const adminToken = popAdminTokenFromImpersonation();
    if (!adminToken) {
      handleLogout();
      return;
    }
    setAuthToken(adminToken);
    try {
      const me = await apiRequest<{ user: User }>('/auth/me');
      setUser(me.user);
      setTutorProfile(null);
      setImpersonatedBy(null);
      setRoute('admin');
    } catch {
      handleLogout();
    }
  };

  const navigateTo = (next: AppRoute) => {
    if ((next === 'dashboard' || next === 'messages' || next === 'admin') && !user) {
      setAuthTab(next === 'admin' ? 'admin' : 'login');
      setRoute('auth');
      return;
    }
    setRoute(next);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#F8F7F4] text-stone-900">
      {route !== 'classroom' && (
        <Navbar
          currentRoute={route}
          onNavigate={navigateTo}
          user={user}
          unreadNotifications={unreadCount}
          impersonatedBy={impersonatedBy}
          onExitImpersonation={handleExitImpersonation}
          onLogout={handleLogout}
        />
      )}

      <main className="flex-1">
        {route === 'home' && (
          <HomeView
            config={config}
            featuredTutors={featuredTutors}
            onSearch={(filters) => {
              setSearchFilters(filters);
              setRoute('search');
            }}
            onSelectTutor={(id) => {
              setSelectedTutorId(id);
              setRoute('tutor-profile');
            }}
            onOpenAuth={(t) => {
              setAuthTab(t || 'login');
              setRoute('auth');
            }}
          />
        )}

        {route === 'auth' && (
          <AuthView
            initialTab={authTab}
            onAuthenticated={handleAuthenticated}
            onOpenLegal={(doc) => setLegalModal(doc)}
          />
        )}

        {route === 'search' && (
          <TutorSearchView
            config={config}
            initialFilters={searchFilters}
            onSelectTutor={(id) => {
              setSelectedTutorId(id);
              setRoute('tutor-profile');
            }}
          />
        )}

        {route === 'tutor-profile' && selectedTutorId && (
          <TutorProfileView
            tutorId={selectedTutorId}
            currentUser={user}
            onBack={() => setRoute('search')}
            onRequireAuth={() => {
              setAuthTab('login');
              setRoute('auth');
            }}
            onBookingConfirmed={() => setRoute('dashboard')}
            onJoinClassroom={(bId) => {
              setActiveClassroomBookingId(bId);
              setRoute('classroom');
            }}
          />
        )}

        {route === 'dashboard' && user?.role === UserRole.Student && (
          <StudentDashboard
            user={user}
            onUserUpdated={setUser}
            onJoinClassroom={(bId) => {
              setActiveClassroomBookingId(bId);
              setRoute('classroom');
            }}
            onFindTutors={() => setRoute('search')}
            onAccountDeleted={() => {
              setAuthToken(null);
              setUser(null);
              setRoute('home');
            }}
          />
        )}

        {route === 'dashboard' && user?.role === UserRole.Tutor && (
          <TutorDashboard
            user={user}
            tutorProfile={tutorProfile}
            config={config}
            onProfileUpdated={setTutorProfile}
            onJoinClassroom={(bId) => {
              setActiveClassroomBookingId(bId);
              setRoute('classroom');
            }}
          />
        )}

        {route === 'classroom' && user && activeClassroomBookingId && (
          <LiveClassroomView
            bookingId={activeClassroomBookingId}
            user={user}
            onExit={() => setRoute('dashboard')}
          />
        )}

        {route === 'messages' && user && (
          <MessagesAndNotificationsView
            user={user}
            onNotificationsRead={() => setUnreadCount(0)}
          />
        )}

        {route === 'admin' && user?.role === UserRole.Admin && (
          <AdminConsoleView
            config={config}
            onConfigUpdated={loadConfigAndFeatured}
            onImpersonated={handleImpersonated}
          />
        )}

        {route === 'help' && <HelpCentreView />}
      </main>

      {route !== 'classroom' && (
        <Footer onNavigate={navigateTo} onOpenLegal={(doc) => setLegalModal(doc)} />
      )}

      {/* Legal & Contact Modal (Chapter 5 Legal Requirements) */}
      {legalModal && (
        <div className="fixed inset-0 z-50 bg-stone-900/40 flex items-center justify-center p-4">
          <div className="bg-white border border-stone-200 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-stone-100 pb-3">
              <h2 className="font-display text-lg font-bold text-stone-900">
                {legalModal === 'terms'
                  ? 'Terms of Service'
                  : legalModal === 'privacy'
                    ? 'Privacy Policy & Minor Data Protection'
                    : legalModal === 'refund'
                      ? 'Cancellation & Refund Policy'
                      : 'Contact Online Tutor Academy'}
              </h2>
              <button type="button" onClick={() => setLegalModal(null)} aria-label="Close modal" className="p-1 text-stone-500">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="text-sm text-stone-700 space-y-2 leading-relaxed">
              {legalModal === 'terms' && (
                <>
                  <p>Online Tutor Academy connects verified tutors with students for scheduled online lessons.</p>
                  <p>All classroom interactions, assignments, and messages must follow academic integrity and child safety standards. Accounts may be suspended for policy violations.</p>
                </>
              )}
              {legalModal === 'privacy' && (
                <>
                  <p>Users under 18 require verified parent/guardian consent. Student and tutor email addresses and phone numbers are never shared across users.</p>
                  <p>Booking, payment, and audit records are retained for 7 years for financial compliance (soft-delete only). You may export or request deletion of your personal data from your dashboard.</p>
                </>
              )}
              {legalModal === 'refund' && (
                <>
                  <p>Free cancellation (100% refund) applies up to {config.freeCancelHours} hours before the scheduled session start time. Cancellations within {config.freeCancelHours} hours receive a 50% refund.</p>
                  <p>Disputes may be filed after a session for full or partial refund review by an Administrator.</p>
                </>
              )}
              {legalModal === 'contact' && (
                <>
                  <p>Academic Operations &amp; Support Desk — Department of Computer &amp; Information Systems, Karachi.</p>
                  <p>Support hours: Monday – Saturday, 09:00 – 21:00 PKT. For urgent session issues, use the Report button inside your dashboard or classroom.</p>
                </>
              )}
            </div>
            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setLegalModal(null)}
                className="px-4 py-2 bg-stone-900 hover:bg-stone-800 text-white text-xs font-medium rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
