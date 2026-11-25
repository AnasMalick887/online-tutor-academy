import type { Server as HttpServer } from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { verifySessionToken } from './auth.ts';
import { db } from './db.ts';
import { UserRole } from '../src/shared/srsConstants.ts';

interface ClassroomClient {
  ws: WebSocket;
  userId: string;
  userName: string;
  role: UserRole;
  bookingId: string;
}

const roomClients = new Map<string, Set<ClassroomClient>>();
const userNotificationSockets = new Map<string, Set<WebSocket>>();

export function pushRealtimeNotification(userId: string, payload: Record<string, unknown>): void {
  const sockets = userNotificationSockets.get(userId);
  if (!sockets) return;
  const serialized = JSON.stringify({ type: 'notification', payload });
  for (const ws of sockets) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(serialized);
    }
  }
}

export function attachWebSocketServer(httpServer: HttpServer): void {
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws) => {
    let clientInfo: ClassroomClient | null = null;
    let notifUserId: string | null = null;

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as {
          type: string;
          token?: string;
          bookingId?: string;
          stroke?: unknown;
          text?: string;
          fileName?: string;
          fileSizeKb?: number;
          recordingEnabled?: boolean;
        };

        if (msg.type === 'auth') {
          const session = msg.token ? verifySessionToken(msg.token) : null;
          if (!session) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired session token.' }));
            ws.close();
            return;
          }
          const userRow = db.prepare('SELECT id, full_name, role FROM users WHERE id = ? AND deleted_at IS NULL').get(session.userId) as
            | { id: string; full_name: string; role: UserRole }
            | undefined;
          if (!userRow) {
            ws.close();
            return;
          }

          notifUserId = userRow.id;
          if (!userNotificationSockets.has(notifUserId)) {
            userNotificationSockets.set(notifUserId, new Set());
          }
          userNotificationSockets.get(notifUserId)!.add(ws);

          if (msg.bookingId) {
            const booking = db
              .prepare('SELECT id, student_id, tutor_id, whiteboard_json FROM bookings WHERE id = ? AND deleted_at IS NULL')
              .get(msg.bookingId) as { id: string; student_id: string; tutor_id: string; whiteboard_json: string } | undefined;

            if (!booking) {
              ws.send(JSON.stringify({ type: 'error', message: 'Classroom booking not found.' }));
              return;
            }
            const isAllowed =
              booking.student_id === userRow.id ||
              booking.tutor_id === userRow.id ||
              session.role === UserRole.Admin;

            if (!isAllowed) {
              ws.send(JSON.stringify({ type: 'error', message: 'Not authorized for this classroom.' }));
              return;
            }

            clientInfo = {
              ws,
              userId: userRow.id,
              userName: userRow.full_name,
              role: session.role,
              bookingId: booking.id,
            };

            if (!roomClients.has(booking.id)) {
              roomClients.set(booking.id, new Set());
            }
            roomClients.get(booking.id)!.add(clientInfo);

            // Resynchronize whiteboard & chat history on connect/reconnect (FR-11 Exception)
            let strokes: unknown[] = [];
            try {
              strokes = JSON.parse(booking.whiteboard_json || '[]');
            } catch {
              strokes = [];
            }

            const chatHistory = db
              .prepare(`
                SELECT ce.id, ce.user_id, ce.event_type, ce.payload_json, ce.created_at
                FROM classroom_events ce
                WHERE ce.booking_id = ? AND ce.event_type IN ('chat', 'file')
                ORDER BY ce.created_at ASC
              `)
              .all(booking.id) as Array<{
              id: string;
              user_id: string;
              event_type: string;
              payload_json: string;
              created_at: string;
            }>;

            const participants = Array.from(roomClients.get(booking.id) || []).map((c) => ({
              userId: c.userId,
              userName: c.userName,
              role: c.role,
            }));

            ws.send(
              JSON.stringify({
                type: 'room_sync',
                strokes,
                chatHistory: chatHistory.map((h) => ({
                  id: h.id,
                  userId: h.user_id,
                  eventType: h.event_type,
                  ...JSON.parse(h.payload_json),
                  createdAt: h.created_at,
                })),
                participants,
              })
            );

            broadcastToRoom(booking.id, {
              type: 'participant_joined',
              userId: userRow.id,
              userName: userRow.full_name,
              role: session.role,
              participants,
            });
          } else {
            ws.send(JSON.stringify({ type: 'auth_ok' }));
          }
          return;
        }

        if (!clientInfo) {
          ws.send(JSON.stringify({ type: 'error', message: 'Authenticate before sending classroom events.' }));
          return;
        }

        const { bookingId, userId, userName } = clientInfo;

        if (msg.type === 'whiteboard_stroke' && msg.stroke) {
          const booking = db.prepare('SELECT whiteboard_json FROM bookings WHERE id = ?').get(bookingId) as
            | { whiteboard_json: string }
            | undefined;
          let strokes: unknown[] = [];
          try {
            strokes = JSON.parse(booking?.whiteboard_json || '[]');
          } catch {
            strokes = [];
          }
          strokes.push(msg.stroke);
          db.prepare('UPDATE bookings SET whiteboard_json = ?, updated_at = ? WHERE id = ?').run(
            JSON.stringify(strokes),
            new Date().toISOString(),
            bookingId
          );
          broadcastToRoom(
            bookingId,
            { type: 'whiteboard_stroke', stroke: msg.stroke, userId },
            ws
          );
        } else if (msg.type === 'whiteboard_clear') {
          db.prepare('UPDATE bookings SET whiteboard_json = ?, updated_at = ? WHERE id = ?').run(
            '[]',
            new Date().toISOString(),
            bookingId
          );
          broadcastToRoom(bookingId, { type: 'whiteboard_clear', userId });
        } else if (msg.type === 'whiteboard_undo') {
          const booking = db.prepare('SELECT whiteboard_json FROM bookings WHERE id = ?').get(bookingId) as
            | { whiteboard_json: string }
            | undefined;
          let strokes: unknown[] = [];
          try {
            strokes = JSON.parse(booking?.whiteboard_json || '[]');
          } catch {
            strokes = [];
          }
          strokes.pop();
          db.prepare('UPDATE bookings SET whiteboard_json = ?, updated_at = ? WHERE id = ?').run(
            JSON.stringify(strokes),
            new Date().toISOString(),
            bookingId
          );
          broadcastToRoom(bookingId, { type: 'whiteboard_sync', strokes });
        } else if (msg.type === 'chat_message' && msg.text && msg.text.trim()) {
          const cleanText = msg.text.trim().slice(0, 1000);
          const id = `evt-${crypto.randomBytes(6).toString('hex')}`;
          const now = new Date().toISOString();
          const payload = { senderName: userName, text: cleanText };
          db.prepare(
            'INSERT INTO classroom_events (id, booking_id, user_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)'
          ).run(id, bookingId, userId, 'chat', JSON.stringify(payload), now);

          broadcastToRoom(bookingId, {
            type: 'chat_message',
            message: { id, userId, eventType: 'chat', ...payload, createdAt: now },
          });
        } else if (msg.type === 'file_share' && msg.fileName) {
          const sizeKb = Number(msg.fileSizeKb || 0);
          if (sizeKb > 10 * 1024) {
            ws.send(JSON.stringify({ type: 'error', message: 'Classroom file exceeds 10 MB limit.' }));
            return;
          }
          const id = `evt-${crypto.randomBytes(6).toString('hex')}`;
          const now = new Date().toISOString();
          const payload = { senderName: userName, fileName: msg.fileName.slice(0, 160), fileSizeKb: sizeKb };
          db.prepare(
            'INSERT INTO classroom_events (id, booking_id, user_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)'
          ).run(id, bookingId, userId, 'file', JSON.stringify(payload), now);

          broadcastToRoom(bookingId, {
            type: 'chat_message',
            message: { id, userId, eventType: 'file', ...payload, createdAt: now },
          });
        } else if (msg.type === 'recording_toggle') {
          broadcastToRoom(bookingId, {
            type: 'recording_notice',
            enabled: Boolean(msg.recordingEnabled),
            byName: userName,
          });
        }
      } catch {
        // ignore malformed JSON frames
      }
    });

    ws.on('close', () => {
      if (notifUserId && userNotificationSockets.has(notifUserId)) {
        userNotificationSockets.get(notifUserId)!.delete(ws);
      }
      if (clientInfo) {
        const set = roomClients.get(clientInfo.bookingId);
        if (set) {
          set.delete(clientInfo);
          const participants = Array.from(set).map((c) => ({
            userId: c.userId,
            userName: c.userName,
            role: c.role,
          }));
          broadcastToRoom(clientInfo.bookingId, {
            type: 'participant_left',
            userId: clientInfo.userId,
            userName: clientInfo.userName,
            participants,
          });
        }
      }
    });
  });
}

function broadcastToRoom(bookingId: string, data: Record<string, unknown>, exclude?: WebSocket): void {
  const set = roomClients.get(bookingId);
  if (!set) return;
  const serialized = JSON.stringify(data);
  for (const client of set) {
    if (client.ws !== exclude && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(serialized);
    }
  }
}
