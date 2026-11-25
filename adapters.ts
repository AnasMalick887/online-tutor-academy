import crypto from 'node:crypto';

/**
 * SRS 2.5.3 & 4.3.1 Adapter Interfaces
 * Isolates third-party video, payment gateway, and email/SMS services behind replaceable adapters.
 */

export interface GatewayChargeRequest {
  bookingId: string;
  amountPkr: number;
  method: 'card' | 'jazzcash' | 'easypaisa';
  accountLast4: string;
  simulateFailure?: boolean;
}

export interface GatewayChargeResult {
  success: boolean;
  gatewayRef: string;
  signature: string;
  error?: string;
}

export interface GatewayRefundResult {
  success: boolean;
  refundRef: string;
  error?: string;
}

const WEBHOOK_SECRET = crypto.randomBytes(24).toString('hex');

export const PaymentGatewayAdapter = {
  /**
   * Simulates PCI-DSS delegated hosted gateway checkout.
   * OTA servers never store full card numbers or PINs—only tokenized reference & last 4 digits.
   */
  processHostedCheckout(req: GatewayChargeRequest): GatewayChargeResult {
    if (req.simulateFailure) {
      return {
        success: false,
        gatewayRef: `GW-FAIL-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        signature: '',
        error: 'Payment declined by issuer or wallet gateway timeout.',
      };
    }

    const gatewayRef = `OTA-PAY-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
    const payload = `${req.bookingId}:${req.amountPkr}:${gatewayRef}`;
    const signature = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');

    return {
      success: true,
      gatewayRef,
      signature,
    };
  },

  verifyWebhookSignature(bookingId: string, amountPkr: number, gatewayRef: string, signature: string): boolean {
    const payload = `${bookingId}:${amountPkr}:${gatewayRef}`;
    const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expected);
    return sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
  },

  processRefund(gatewayRef: string, amountPkr: number): GatewayRefundResult {
    if (!gatewayRef || amountPkr <= 0) {
      return { success: false, refundRef: '', error: 'Invalid refund parameters.' };
    }
    return {
      success: true,
      refundRef: `OTA-REF-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    };
  },
};

export const VideoRoomAdapter = {
  /**
   * Generates a short-lived room access token for WebRTC / Classroom WebSocket synchronization (FR-10).
   */
  issueRoomToken(bookingId: string, userId: string, role: string): string {
    const exp = Date.now() + 3 * 60 * 60 * 1000;
    const body = Buffer.from(JSON.stringify({ bookingId, userId, role, exp })).toString('base64url');
    const sig = crypto.createHmac('sha256', WEBHOOK_SECRET).update(body).digest('base64url');
    return `${body}.${sig}`;
  },
};

export interface DeliveryAttemptResult {
  delivered: boolean;
  retryCount: number;
  statusLabel: string;
}

export const MessagingAdapter = {
  /**
   * Simulates email/SMS delivery with up to 3 retries (FR-17).
   */
  dispatch(channel: 'email' | 'sms' | 'in_app', recipient: string, title: string, _body: string): DeliveryAttemptResult {
    if (!recipient) {
      return { delivered: false, retryCount: 3, statusLabel: 'Failed after 3 retries' };
    }
    return {
      delivered: true,
      retryCount: 0,
      statusLabel: channel === 'in_app' ? 'Delivered (In-App)' : `Delivered via ${channel.toUpperCase()} to ${recipient}`,
    };
  },
};
