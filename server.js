// server.js — the main Express app
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { OAuth2Client } = require("google-auth-library");
const pool = require("./db");
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

if (!GOOGLE_CLIENT_ID) {
  console.warn("WARNING: GOOGLE_CLIENT_ID is not configured.");
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const { sendOrderConfirmation, sendPasswordResetEmail } = require("./mailer");
const app = express();

// Render (and most PaaS hosts) sit behind a reverse proxy — trust the
// X-Forwarded-For header so req.ip reflects the real client IP. This
// matters for the password-reset rate limiter below.
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("NeoFragrances API is running.");
});
// ---------- Google OAuth Configuration ----------
app.get("/api/config/google-client-id", (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(503).json({
      error: "Google Sign-In is not configured.",
    });
  }

  res.json({
    clientId: process.env.GOOGLE_CLIENT_ID,
  });
});

// ---------- Auth middleware: checks the login token on protected routes ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "You must be logged in." });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
}

// ---------- Products ----------
app.get("/api/products", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM products WHERE deleted_at IS NULL"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong fetching products." });
  }
});

// ---------- Register ----------
app.post("/api/register", async (req, res) => {
  const { fullName, email, phone, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: "Full name, email, and password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  try {
    const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (full_name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, 'customer')",
      [fullName, email, phone || null, passwordHash]
    );

    const user = { id: result.insertId, full_name: fullName, email, role: "customer" };
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong creating your account." });
  }
});

// ---------- Login ----------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong logging you in." });
  }
});
// ---------- Google Login ----------
app.post("/api/auth/google", async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({
      error: "Google credential is required.",
    });
  }

  if (!GOOGLE_CLIENT_ID) {
    return res.status(500).json({
      error: "Google Sign-In is not configured on the server.",
    });
  }

  try {
    // Verify the Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (!payload) {
      return res.status(401).json({
        error: "Invalid Google account information.",
      });
    }

    const {
      sub: googleId,
      email,
      name,
      picture,
      email_verified,
    } = payload;

    // Make sure Google verified the email
    if (!email || !email_verified) {
      return res.status(401).json({
        error: "Your Google email could not be verified.",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if this email already has a NeoFragrances account
    const [existingUsers] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [normalizedEmail]
    );

    let user;

    if (existingUsers.length > 0) {
      // Existing NeoFragrances account
      user = existingUsers[0];

      console.log(
        `Google login: existing user ${user.email}`
      );
    } else {
      // Create a new NeoFragrances customer account
      //
      // Google accounts don't need a local password.
      // We generate a random password hash because your
      // current users table expects password_hash.
      const randomPassword = crypto.randomBytes(32).toString("hex");
      const passwordHash = await bcrypt.hash(randomPassword, 10);

      const [result] = await pool.query(
        `INSERT INTO users
          (full_name, email, phone, password_hash, role)
         VALUES (?, ?, ?, ?, 'customer')`,
        [
          name || "NeoFragrances Customer",
          normalizedEmail,
          null,
          passwordHash,
        ]
      );

      user = {
        id: result.insertId,
        full_name: name || "NeoFragrances Customer",
        email: normalizedEmail,
        role: "customer",
      };

      console.log(
        `Google login: created new user ${normalizedEmail}`
      );
    }

    // Generate the same JWT used by normal NeoFragrances login
    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        picture: picture || null,
      },
    });
  } catch (err) {
    console.error("Google authentication error:", err);

    res.status(401).json({
      error: "Google sign-in failed. Please try again.",
    });
  }
});
// ---------- Checkout ----------
app.post("/api/checkout", requireAuth, async (req, res) => {
  const { items, addressId, couponId } = req.body; // [{ productId, qty }], addressId, couponId

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Your cart is empty." });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const ids = items.map(i => i.productId);
    const [products] = await connection.query(
      `SELECT id, price, stock_qty FROM products WHERE id IN (?) AND deleted_at IS NULL`,
      [ids]
    );

    let total = 0;
    const itemDetails = [];
    for (const item of items) {
      const product = products.find(p => Number(p.id) === Number(item.productId));
      if (!product) {
          console.error("Product mismatch — item.productId:", item.productId, "available product IDs:", products.map(p => p.id));
          throw new Error("One of the items in your order is no longer available.");
        }
      if (product.stock_qty < item.qty) throw new Error(`Not enough stock for one of the items in your cart.`);
      total += Number(product.price) * item.qty;
      itemDetails.push({ productId: item.productId, qty: item.qty, price: product.price });
    }

    let discount = 0;
    let appliedCoupon = null;
    if (couponId) {
      const [couponRows] = await connection.query("SELECT * FROM coupons WHERE id = ?", [couponId]);
      if (couponRows.length > 0) {
        appliedCoupon = couponRows[0];
        if (appliedCoupon.discount_percent) {
          discount = total * (Number(appliedCoupon.discount_percent) / 100);
        } else if (appliedCoupon.discount_amount) {
          discount = Number(appliedCoupon.discount_amount);
        }
        discount = Math.min(discount, total);
      }
    }
    const finalTotal = total - discount;

    const [orderResult] = await connection.query(
      "INSERT INTO orders (user_id, address_id, coupon_id, total, status) VALUES (?, ?, ?, ?, 'Pending')",
      [req.user.id, addressId || null, couponId || null, finalTotal]
    );
    const orderId = orderResult.insertId;

    for (const item of itemDetails) {
      await connection.query(
        "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)",
        [orderId, item.productId, item.qty, item.price]
      );
      await connection.query(
        "UPDATE products SET stock_qty = stock_qty - ? WHERE id = ?",
        [item.qty, item.productId]
      );
    }

    if (appliedCoupon) {
      await connection.query("UPDATE coupons SET times_used = times_used + 1 WHERE id = ?", [appliedCoupon.id]);
    }

    await connection.commit();
    res.status(201).json({ orderId, total: finalTotal, discount });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: err.message || "Checkout failed." });
  } finally {
    connection.release();
  }
});

// ---------- A logged-in customer's own order history ----------
app.get("/api/my-orders", requireAuth, async (req, res) => {
  try {
    const [orders] = await pool.query(
      "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
      [req.user.id]
    );
    if (orders.length === 0) return res.json([]);

    const orderIds = orders.map(o => o.id);
    const [items] = await pool.query(
      `SELECT order_items.order_id, order_items.quantity, order_items.price_at_purchase, products.name
       FROM order_items
       JOIN products ON order_items.product_id = products.id
       WHERE order_items.order_id IN (?)`,
      [orderIds]
    );

    const itemsByOrder = {};
    items.forEach(item => {
      if (!itemsByOrder[item.order_id]) itemsByOrder[item.order_id] = [];
      itemsByOrder[item.order_id].push(item);
    });

    res.json(orders.map(o => ({ ...o, items: itemsByOrder[o.id] || [] })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch your orders." });
  }
});
// ---------- Track Order (guest/customer lookup) ----------
app.post("/api/track-order", async (req, res) => {
  const { orderId, email } = req.body;

  if (!orderId || !email) {
    return res.status(400).json({
      error: "Order number and email address are required."
    });
  }

  try {
    // Find the order and verify that the supplied email
    // belongs to the customer who placed the order.
    const [orders] = await pool.query(
      `SELECT orders.id,
              orders.status,
              orders.total,
              orders.created_at,
              users.email
       FROM orders
       JOIN users ON orders.user_id = users.id
       WHERE orders.id = ?
         AND LOWER(users.email) = LOWER(?)`,
      [orderId, email.trim()]
    );

    if (orders.length === 0) {
      return res.status(404).json({
        error: "We could not find an order matching that order number and email address."
      });
    }

    const order = orders[0];

    // Get the products/items belonging to this order
    const [items] = await pool.query(
      `SELECT order_items.quantity,
              order_items.price_at_purchase,
              products.name
       FROM order_items
       JOIN products ON order_items.product_id = products.id
       WHERE order_items.order_id = ?`,
      [order.id]
    );

    res.json({
      id: order.id,
      status: order.status,
      total: order.total,
      created_at: order.created_at,
      items
    });

  } catch (err) {
    console.error("Track order error:", err);

    res.status(500).json({
      error: "Something went wrong while tracking your order."
    });
  }
});
// ---------- Auth middleware: admin-only routes ----------
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access only." });
    }
    next();
  });
}

// ---------- Admin: Create Product ----------
app.post("/api/admin/products", requireAdmin, async (req, res) => {
  const { name, brand, category, price, stock_qty, badge, image, top_notes, middle_notes, base_notes } = req.body;
  if (!name || !brand || !category || price == null) {
    return res.status(400).json({ error: "Name, brand, category, and price are required." });
  }
  try {
    const [result] = await pool.query(
      `INSERT INTO products (name, brand, category, price, stock_qty, badge, image, top_notes, middle_notes, base_notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [name, brand, category, price, stock_qty || 0, badge || null, image || null, top_notes || null, middle_notes || null, base_notes || null]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not create product." });
  }
});

// ---------- Admin: Update Product ----------
app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
  const { name, brand, category, price, stock_qty, badge, image, top_notes, middle_notes, base_notes } = req.body;
  try {
    await pool.query(
      `UPDATE products SET name=?, brand=?, category=?, price=?, stock_qty=?, badge=?, image=?, top_notes=?, middle_notes=?, base_notes=? WHERE id=?`,
      [name, brand, category, price, stock_qty, badge || null, image, top_notes, middle_notes, base_notes, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update product." });
  }
});

// ---------- Admin: Delete Product (soft-delete) ----------
app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query("UPDATE products SET deleted_at = NOW() WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not delete product." });
  }
});

// ---------- Admin: Update Stock ----------
app.patch("/api/admin/products/:id/stock", requireAdmin, async (req, res) => {
  const { stock_qty } = req.body;
  if (stock_qty == null || stock_qty < 0) {
    return res.status(400).json({ error: "Invalid stock quantity." });
  }
  try {
    await pool.query("UPDATE products SET stock_qty = ? WHERE id = ?", [stock_qty, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update stock." });
  }
});

// ---------- Admin: Get all orders ----------
app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT orders.*, users.full_name AS customer_name, users.email AS customer_email
      FROM orders
      JOIN users ON orders.user_id = users.id
      ORDER BY orders.created_at DESC
    `);
    const [itemCounts] = await pool.query(`
      SELECT order_id, COUNT(*) AS item_count FROM order_items GROUP BY order_id
    `);
    const countMap = {};
    itemCounts.forEach(r => { countMap[r.order_id] = r.item_count; });
    res.json(orders.map(o => ({ ...o, item_count: countMap[o.id] || 0 })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch orders." });
  }
});

// ---------- Admin: Update order status ----------
app.patch("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
  const { status } = req.body;
  const validStatuses = ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: "Invalid status." });
  }
  try {
    await pool.query("UPDATE orders SET status = ? WHERE id = ?", [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not update order status." });
  }
});

// ---------- Admin: Get all customers ----------
app.get("/api/admin/customers", requireAdmin, async (req, res) => {
  try {
    const [customers] = await pool.query(`
      SELECT users.id, users.full_name, users.email, users.created_at,
             COUNT(orders.id) AS order_count
      FROM users
      LEFT JOIN orders ON orders.user_id = users.id
      WHERE users.role = 'customer'
      GROUP BY users.id
      ORDER BY users.created_at DESC
    `);
    res.json(customers);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch customers." });
  }
});

// ---------- Wishlist ----------
app.get("/api/wishlist", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT products.* FROM wishlist
       JOIN products ON wishlist.product_id = products.id
       WHERE wishlist.user_id = ? AND products.deleted_at IS NULL
       ORDER BY wishlist.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch wishlist." });
  }
});

app.post("/api/wishlist", requireAuth, async (req, res) => {
  const { productId } = req.body;
  if (!productId) return res.status(400).json({ error: "productId is required." });
  try {
    await pool.query("INSERT IGNORE INTO wishlist (user_id, product_id) VALUES (?, ?)", [req.user.id, productId]);
    res.status(201).json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not add to wishlist." });
  }
});

app.delete("/api/wishlist/:productId", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM wishlist WHERE user_id = ? AND product_id = ?", [req.user.id, req.params.productId]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not remove from wishlist." });
  }
});

// ---------- Reviews ----------
app.get("/api/products/:id/reviews", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT reviews.*, users.full_name FROM reviews
       JOIN users ON reviews.user_id = users.id
       WHERE reviews.product_id = ?
       ORDER BY reviews.created_at DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch reviews." });
  }
});

app.post("/api/products/:id/reviews", requireAuth, async (req, res) => {
  const { rating, comment } = req.body;
  const productId = req.params.id;
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "Rating must be between 1 and 5." });
  }
  try {
    const [purchaseCheck] = await pool.query(
      `SELECT order_items.id FROM order_items
       JOIN orders ON order_items.order_id = orders.id
       WHERE orders.user_id = ? AND order_items.product_id = ? LIMIT 1`,
      [req.user.id, productId]
    );
    const isVerified = purchaseCheck.length > 0;

    await pool.query(
      "INSERT INTO reviews (product_id, user_id, rating, comment, is_verified_purchase) VALUES (?, ?, ?, ?, ?)",
      [productId, req.user.id, rating, comment || null, isVerified]
    );

    const [agg] = await pool.query(
      "SELECT AVG(rating) AS avgRating, COUNT(*) AS count FROM reviews WHERE product_id = ?",
      [productId]
    );
    await pool.query("UPDATE products SET avg_rating = ?, review_count = ? WHERE id = ?", [agg[0].avgRating, agg[0].count, productId]);

    res.status(201).json({ success: true, isVerified });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not submit review." });
  }
});

// ---------- Addresses ----------
app.get("/api/addresses", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, created_at DESC",
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not fetch addresses." });
  }
});

app.post("/api/addresses", requireAuth, async (req, res) => {
  const { label, fullName, phone, addressLine1, addressLine2, city, region, country, isDefault } = req.body;
  if (!fullName || !addressLine1 || !city || !country) {
    return res.status(400).json({ error: "Full name, address, city, and country are required." });
  }
  try {
    if (isDefault) {
      await pool.query("UPDATE addresses SET is_default = FALSE WHERE user_id = ?", [req.user.id]);
    }
    const [result] = await pool.query(
      `INSERT INTO addresses (user_id, label, full_name, phone, address_line1, address_line2, city, region, country, is_default)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, label || "Home", fullName, phone || null, addressLine1, addressLine2 || null, city, region || null, country, !!isDefault]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not save address." });
  }
});

// ============================================================
// ---------- Password Reset (real, email-based flow) ---------
// ============================================================
//
// Security design:
//  - The raw token is sent ONLY by email, never in an API response.
//  - Only a SHA-256 hash of the token is stored in the database, so a
//    leaked/stolen database dump can't be used to reset accounts.
//  - Tokens expire after 1 hour and are single-use (marked used_at,
//    and re-checked with `used_at IS NULL` on every lookup).
//  - Requesting a new link invalidates any previous unused links for
//    that user.
//  - The forgot-password endpoint always returns the same generic
//    message, whether or not the email is registered, so it can't be
//    used to enumerate accounts.
//  - Lightweight in-memory rate limiting/cooldown guards against abuse.
//    This resets if the server restarts and isn't shared across
//    multiple server instances — fine for this project's scale, but a
//    production deployment on multiple instances should move this to
//    something shared (e.g. express-rate-limit backed by Redis/DB).

const RESET_IP_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RESET_IP_MAX_REQUESTS = 5;           // per IP, per window
const RESET_EMAIL_COOLDOWN_MS = 60 * 1000; // 60 seconds between requests for the same email

const resetIpHits = new Map();         // ip -> [timestamps]
const resetEmailCooldowns = new Map(); // normalizedEmail -> last request timestamp

function isIpRateLimited(ip) {
  const now = Date.now();
  const hits = (resetIpHits.get(ip) || []).filter(t => now - t < RESET_IP_WINDOW_MS);
  resetIpHits.set(ip, hits);
  return hits.length >= RESET_IP_MAX_REQUESTS;
}
function recordIpRequest(ip) {
  const hits = resetIpHits.get(ip) || [];
  hits.push(Date.now());
  resetIpHits.set(ip, hits);
}
function isEmailOnCooldown(email) {
  const last = resetEmailCooldowns.get(email);
  return !!last && (Date.now() - last) < RESET_EMAIL_COOLDOWN_MS;
}
function recordEmailCooldown(email) {
  resetEmailCooldowns.set(email, Date.now());
}
// Periodic cleanup so these maps don't grow forever on a long-running process.
setInterval(() => {
  const now = Date.now();
  for (const [email, ts] of resetEmailCooldowns) {
    if (now - ts > RESET_EMAIL_COOLDOWN_MS) resetEmailCooldowns.delete(email);
  }
  for (const [ip, hits] of resetIpHits) {
    const fresh = hits.filter(t => now - t < RESET_IP_WINDOW_MS);
    if (fresh.length === 0) resetIpHits.delete(ip); else resetIpHits.set(ip, fresh);
  }
}, 60 * 60 * 1000).unref();

function hashResetToken(rawToken) {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}

// ---------- Forgot Password ----------
app.post("/api/forgot-password", async (req, res) => {
  const ip = req.ip;
  const GENERIC = { message: "If an account exists with that email, we've sent you a password reset link." };

  if (isIpRateLimited(ip)) {
    return res.status(429).json({ error: "Too many requests. Please try again later." });
  }
  recordIpRequest(ip);

  const email = (req.body?.email || "").trim();
  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  // Same-email cooldown: respond with the generic message either way,
  // so a repeated submission never reveals whether the account exists.
  if (isEmailOnCooldown(email)) {
    return res.json(GENERIC);
  }
  recordEmailCooldown(email);

  try {
    const [users] = await pool.query("SELECT id, full_name FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      return res.json(GENERIC);
    }

    const user = users[0];

    // Invalidate any previous unused reset tokens for this user before
    // issuing a new one.
    await pool.query("DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL", [user.id]);

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashResetToken(rawToken);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
      "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
      [user.id, tokenHash, expiresAt]
    );

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${rawToken}`;

    try {
      await sendPasswordResetEmail({ to: email, customerName: user.full_name, resetUrl });
    } catch (emailErr) {
      // Never surface email-delivery failures to the client — that would
      // leak whether the account exists, and could expose infra details.
      console.error("Password reset email failed to send:", emailErr);
    }

    return res.json(GENERIC);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ---------- Verify a reset token (used by reset-password.html on load) ----------
app.get("/api/reset-password/verify", async (req, res) => {
  const token = req.query?.token;
  if (!token) return res.json({ valid: false });

  try {
    const tokenHash = hashResetToken(token);
    const [rows] = await pool.query(
      "SELECT id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() LIMIT 1",
      [tokenHash]
    );
    res.json({ valid: rows.length > 0 });
  } catch (err) {
    console.error(err);
    res.json({ valid: false });
  }
});

// ---------- Reset Password ----------
app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: "Token and new password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  const INVALID = { error: "This password reset link is invalid or has expired. Please request a new one." };

  try {
    const tokenHash = hashResetToken(token);
    const [rows] = await pool.query(
      "SELECT * FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() LIMIT 1",
      [tokenHash]
    );
    if (rows.length === 0) {
      return res.status(400).json(INVALID);
    }

    const resetRecord = rows[0];
    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, resetRecord.user_id]);

    // Mark this token used (audit trail) and clear out any other stray
    // unused tokens for this user so the link can never be reused.
    await pool.query("UPDATE password_resets SET used_at = NOW() WHERE id = ?", [resetRecord.id]);
    await pool.query("DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL", [resetRecord.user_id]);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not reset your password." });
  }
});

// ---------- Coupons ----------
app.post("/api/coupons/validate", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Coupon code is required." });

  try {
    const [rows] = await pool.query("SELECT * FROM coupons WHERE code = ?", [code.toUpperCase()]);
    if (rows.length === 0) return res.status(404).json({ error: "Invalid coupon code." });

    const coupon = rows[0];
    if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
      return res.status(400).json({ error: "This coupon has expired." });
    }
    if (coupon.usage_limit !== null && coupon.times_used >= coupon.usage_limit) {
      return res.status(400).json({ error: "This coupon has reached its usage limit." });
    }

    res.json({
      id: coupon.id,
      code: coupon.code,
      discountPercent: coupon.discount_percent,
      discountAmount: coupon.discount_amount,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not validate coupon." });
  }
});

// ---------- Payments (Paystack) ----------
app.post("/api/payments/initialize", requireAuth, async (req, res) => {
  const { items, addressId, couponId } = req.body;

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Your cart is empty." });
  }

  try {
    const [userRows] = await pool.query("SELECT email FROM users WHERE id = ?", [req.user.id]);
    if (userRows.length === 0) return res.status(404).json({ error: "User not found." });
    const email = userRows[0].email;

    const ids = items.map(i => i.productId);
    const [products] = await pool.query(
      `SELECT id, price, stock_qty FROM products WHERE id IN (?) AND deleted_at IS NULL`,
      [ids]
    );

    let total = 0;
    for (const item of items) {
      const product = products.find(p => p.id === item.productId);
      if (!product) return res.status(400).json({ error: "One of the items in your cart is no longer available." });
      if (product.stock_qty < item.qty) return res.status(400).json({ error: "Not enough stock for one of the items in your cart." });
      total += Number(product.price) * item.qty;
    }

    let discount = 0;
    if (couponId) {
      const [couponRows] = await pool.query("SELECT * FROM coupons WHERE id = ?", [couponId]);
      if (couponRows.length > 0) {
        const c = couponRows[0];
        if (c.discount_percent) discount = total * (Number(c.discount_percent) / 100);
        else if (c.discount_amount) discount = Number(c.discount_amount);
        discount = Math.min(discount, total);
      }
    }
    const shipping = total > 0 ? 8 : 0;
    const finalTotal = total - discount + shipping;
    const reference = `NF-${Date.now()}-${req.user.id}`;

    console.log("Callback URL being sent to Paystack:", `${process.env.FRONTEND_URL}/payment-callback.html`);
    const paystackRes = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        amount: Math.round(finalTotal * 100), // Paystack expects the smallest currency unit (pesewas)
        reference,
        callback_url: `${process.env.FRONTEND_URL}/payment-callback.html`,
        metadata: { userId: req.user.id, items, addressId: addressId || null, couponId: couponId || null },
      }),
    });
    const paystackData = await paystackRes.json();
    if (!paystackData.status) {
      return res.status(500).json({ error: paystackData.message || "Could not start payment." });
    }

    res.json({ authorizationUrl: paystackData.data.authorization_url, reference });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not initialize payment." });
  }
});

app.get("/api/payments/verify/:reference", requireAuth, async (req, res) => {
  const { reference } = req.params;

  try {
    const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const verifyData = await verifyRes.json();

    if (!verifyData.status || verifyData.data.status !== "success") {
      return res.status(400).json({ error: "Payment was not successful." });
    }

    const [existing] = await pool.query("SELECT id, total FROM orders WHERE payment_reference = ?", [reference]);
    if (existing.length > 0) {
      return res.json({ orderId: existing[0].id, total: existing[0].total, alreadyProcessed: true });
    }

    const { items, addressId, couponId, userId } = verifyData.data.metadata;
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      const ids = items.map(i => i.productId);
      const [products] = await connection.query(
        `SELECT id, name, price, stock_qty FROM products WHERE id IN (?) AND deleted_at IS NULL`,
        [ids]
      );

      let total = 0;
      const itemDetails = [];
      for (const item of items) {
        const product = products.find(p => Number(p.id) === Number(item.productId));
        if (!product) {
          console.error("Product mismatch — item.productId:", item.productId, "available product IDs:", products.map(p => p.id));
          throw new Error("One of the items in your order is no longer available.");
        }
        total += Number(product.price) * item.qty;
        itemDetails.push({ productId: item.productId, qty: item.qty, price: product.price, name: product.name });
      }

      let discount = 0;
      let appliedCoupon = null;
      if (couponId) {
        const [couponRows] = await connection.query("SELECT * FROM coupons WHERE id = ?", [couponId]);
        if (couponRows.length > 0) {
          appliedCoupon = couponRows[0];
          if (appliedCoupon.discount_percent) discount = total * (Number(appliedCoupon.discount_percent) / 100);
          else if (appliedCoupon.discount_amount) discount = Number(appliedCoupon.discount_amount);
          discount = Math.min(discount, total);
        }
      }
      const finalTotal = total - discount;

      const [orderResult] = await connection.query(
        "INSERT INTO orders (user_id, address_id, coupon_id, total, status, payment_reference) VALUES (?, ?, ?, ?, 'Processing', ?)",
        [userId, addressId || null, couponId || null, finalTotal, reference]
      );
      const orderId = orderResult.insertId;

      for (const item of itemDetails) {
        await connection.query(
          "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)",
          [orderId, item.productId, item.qty, item.price]
        );
        await connection.query("UPDATE products SET stock_qty = stock_qty - ? WHERE id = ?", [item.qty, item.productId]);
      }

      if (appliedCoupon) {
        await connection.query("UPDATE coupons SET times_used = times_used + 1 WHERE id = ?", [appliedCoupon.id]);
      }

      await connection.commit();

      // Send the confirmation email — wrapped so a failed email never breaks the order itself
      try {
        const [userRows] = await pool.query("SELECT full_name, email FROM users WHERE id = ?", [userId]);
        if (userRows.length > 0) {
          await sendOrderConfirmation({
            to: userRows[0].email,
            customerName: userRows[0].full_name,
            orderId,
            items: itemDetails,
            total: finalTotal,
          });
        }
      } catch (emailErr) {
        console.error("Order confirmation email failed to send:", emailErr);
      }

      res.status(201).json({ orderId, total: finalTotal });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Could not verify payment." });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`NeoFragrances API running at http://localhost:${PORT}`);
});
