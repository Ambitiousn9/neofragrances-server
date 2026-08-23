// mailer.js — sends order confirmation emails via Gmail
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

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

  await transporter.sendMail({
    from: `"NeoFragrances" <${process.env.EMAIL_USER}>`,
    to,
    subject: `Order Confirmation — #${orderId}`,
    html,
  });
}

module.exports = { sendOrderConfirmation };