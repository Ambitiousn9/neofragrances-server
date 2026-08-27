// mailer.js — sends order confirmation and password-reset emails via Resend
//
// WHY RESEND INSTEAD OF RAW SMTP: raw SMTP (Gmail, port 465/587) from
// Render's free tier consistently times out (ETIMEDOUT on CONN) — the
// TCP connection to Gmail's mail servers never completes, regardless of
// port or IPv4/IPv6. This is a known pattern on PaaS free tiers, which
// commonly restrict outbound SMTP while leaving normal HTTPS traffic
// open. Resend sends over a plain HTTPS API call (port 443), which
// sidesteps the problem entirely.
//
// No new npm dependency needed — this uses the same global `fetch()`
// already used elsewhere in this project (see the Paystack calls in
// server.js), just pointed at Resend's REST API instead.

const RESEND_API_URL = "https://api.resend.com/emails";

// Until a domain is verified in the Resend dashboard, Resend requires
// sending FROM this sandbox address, and only allows sending TO the
// email address the Resend account was signed up with. Once a domain is
// verified (Resend → Domains), set RESEND_FROM_EMAIL to something like
// "NeoFragrances <noreply@yourdomain.com>" — no code change needed.
const FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "NeoFragrances <onboarding@resend.dev>";

async function sendViaResend({ to, subject, html }) {
  const res = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to,
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Resend API error (${res.status}): ${errorBody}`);
  }

  return res.json();
}

async function sendOrderConfirmation({ to, customerName, orderId, items, total }) {
  const itemRows = items.map(item => `
    <tr>
      <td style="padding:10px 0; border-bottom:1px solid #E4DAD0;">${item.name} &times; ${item.qty}</td>
      <td style="padding:10px 0; border-bottom:1px solid #E4DAD0; text-align:right;">$${(item.price * item.qty).toFixed(2)}</td>
    </tr>`).join("");

  const html = `
  <div style="font-family: Arial, sans-serif; max-width:520px; margin:0 auto; color:#2B1B2E;">
    <div style="background:#2B1B2E; padding:24px; text-align:center;">
      <span style="font-size:22px; font-weight:bold; color:#fff;">Neo<span style="color:#B8935F;">Fragrances</span></span>
    </div>
    <div style="padding:30px 24px;">
      <h2 style="margin-top:0;">Thank you, ${customerName}!</h2>
      <p style="color:#5C4A5E;">Your order has been confirmed and is now being processed.</p>
      <p style="font-weight:bold; margin-top:20px;">Order #${orderId}</p>
      <table style="width:100%; border-collapse:collapse; margin-top:10px;">
        ${itemRows}
      </table>
      <table style="width:100%; padding-top:16px;">
        <tr>
          <td style="font-weight:bold; font-size:16px;">Total</td>
          <td style="font-weight:bold; font-size:16px; text-align:right;">$${Number(total).toFixed(2)}</td>
        </tr>
      </table>
      <p style="color:#5C4A5E; margin-top:30px; font-size:13px;">You can track this order anytime from your account under "My Orders."</p>
    </div>
    <div style="background:#FAF6F0; padding:16px; text-align:center; font-size:12px; color:#5C4A5E;">
      &copy; 2026 NeoFragrances. All rights reserved.
    </div>
  </div>`;

  await sendViaResend({
    to,
    subject: `Order Confirmation — #${orderId}`,
    html,
  });
}

/**
 * Sends the password-reset email. The reset link is only ever sent here —
 * it is never returned in an API response or rendered in the frontend.
 */
async function sendPasswordResetEmail({ to, customerName, resetUrl }) {
  const html = `
  <div style="font-family: Arial, sans-serif; max-width:520px; margin:0 auto; color:#2B1B2E;">
    <div style="background:#2B1B2E; padding:24px; text-align:center;">
      <span style="font-size:22px; font-weight:bold; color:#fff;">Neo<span style="color:#B8935F;">Fragrances</span></span>
    </div>
    <div style="padding:32px 28px;">
      <h2 style="margin-top:0; font-family: Georgia, serif;">Reset Your Password</h2>
      <p style="color:#5C4A5E; line-height:1.6;">
        Hi ${customerName || "there"}, we received a request to reset the password for your NeoFragrances
        account. Click the button below to choose a new password. This link will expire in
        <strong>1 hour</strong>.
      </p>
      <div style="text-align:center; margin:32px 0;">
        <a href="${resetUrl}"
           style="background:#6B2737; color:#ffffff; text-decoration:none; font-weight:bold; font-size:15px; padding:14px 34px; border-radius:6px; display:inline-block;">
          Reset Password
        </a>
      </div>
      <p style="color:#5C4A5E; font-size:13px; line-height:1.6;">
        If the button above doesn't work, copy and paste this link into your browser:<br>
        <a href="${resetUrl}" style="color:#6B2737; word-break:break-all;">${resetUrl}</a>
      </p>
      <p style="color:#5C4A5E; font-size:13px; margin-top:28px; padding-top:20px; border-top:1px solid #E4DAD0;">
        If you didn't request a password reset, you can safely ignore this email — your password will
        remain unchanged.
      </p>
    </div>
    <div style="background:#FAF6F0; padding:16px; text-align:center; font-size:12px; color:#5C4A5E;">
      &copy; 2026 NeoFragrances. All rights reserved.
    </div>
  </div>`;

  await sendViaResend({
    to,
    subject: "Reset Your NeoFragrances Password",
    html,
  });
}

module.exports = { sendOrderConfirmation, sendPasswordResetEmail };
