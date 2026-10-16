require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { initializeApp, cert, getApps, applicationDefault } = require("firebase-admin/app");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const isProduction = process.env.NODE_ENV === "production";
if (isProduction && !String(process.env.ALLOWED_ORIGINS || "").trim()) {
  console.error("Missing required environment variable: ALLOWED_ORIGINS");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const allowedOrigins = String(process.env.ALLOWED_ORIGINS || "http://127.0.0.1:5500,http://localhost:5500,http://localhost:3000")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "20kb" }));
app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); });
app.use((req, res, next) => {
  req.requestId = String(req.headers["x-request-id"] || crypto.randomUUID());
  res.set("X-Request-Id", req.requestId);
  const startedAt = Date.now();
  res.on("finish", () => {
    console.log(JSON.stringify({
      level: "info",
      type: "http_request",
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - startedAt
    }));
  });
  next();
});
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
}));

// Public phone/email lookup endpoints ke liye sakht limit (enumeration/brute-force rokne ke liye)
const authLookupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many attempts. Please try again after some time." }
});
app.use("/api/auth/check-phone", authLookupLimiter);
app.use("/api/auth/find-email", authLookupLimiter);

let adminAuth = null;
let adminDb = null;
let firebaseInitError = null;

function loadLocalServiceAccount() {
  const configuredPath = String(process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "").trim();
  // serviceAccountKey.json / serviceAccountkey.json dono naam chalenge (Linux case-sensitive hai)
  const defaults = fs.readdirSync(__dirname)
    .filter((name) => name.toLowerCase() === "serviceaccountkey.json")
    .map((name) => path.join(__dirname, name));
  const candidates = [
    configuredPath && path.resolve(__dirname, configuredPath),
    ...defaults
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    const serviceAccount = JSON.parse(fs.readFileSync(candidate, "utf8"));
    return { serviceAccount, source: candidate };
  }
  return null;
}

function initFirebaseAdmin() {
  if (getApps().length) {
    adminAuth = getAuth();
    adminDb = getFirestore();
    return true;
  }

  try {
    if (String(process.env.FIREBASE_SERVICE_ACCOUNT || "").trim()) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      initializeApp({ credential: cert(serviceAccount) });
      console.log("Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT");
    } else {
      const local = loadLocalServiceAccount();
      if (local) {
        initializeApp({ credential: cert(local.serviceAccount) });
        console.log(`Firebase Admin initialized from ${local.source}`);
      } else if (isProduction) {
        initializeApp({ credential: applicationDefault() });
        console.log("Firebase Admin initialized with application default credentials");
      } else {
        firebaseInitError = new Error(
          "Firebase credentials not found. Download serviceAccountKey.json from Firebase Console and place it in the backend folder."
        );
        console.warn(firebaseInitError.message);
        return false;
      }
    }

    adminAuth = getAuth();
    adminDb = getFirestore();
    firebaseInitError = null;
    return true;
  } catch (error) {
    firebaseInitError = error;
    console.error("Firebase Admin initialization failed:", error.message);
    return false;
  }
}

initFirebaseAdmin();

function requireFirebase(req, res, next) {
  if (adminAuth && adminDb) return next();
  return res.status(503).json({
    success: false,
    message: "Firebase backend is not configured. Add backend/serviceAccountKey.json and restart the server."
  });
}

async function requireAuth(req, res, next) {
  if (!adminAuth || !adminDb) return requireFirebase(req, res, next);
  try {
    const header = String(req.headers.authorization || "");
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }

    const token = header.slice(7).trim();
    req.authUser = await adminAuth.verifyIdToken(token, true);
    return next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired login" });
  }
}

async function getProfile(uid) {
  const snap = await adminDb.collection("users").doc(uid).get();
  return snap.exists ? snap.data() || {} : null;
}


async function writeAdminAudit(req, action, targetUid, metadata = {}) {
  try {
    const ownerUid = req.authProfile?.ownerUid || req.authUser?.uid || null;
    await adminDb.collection("adminAuditLogs").add({
      action,
      actorUid: req.authUser?.uid || null,
      ownerUid,
      targetUid: targetUid || null,
      requestId: req.requestId || null,
      metadata,
      createdAt: FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error("admin-audit-write failed", error);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const profile = await getProfile(req.authUser.uid);
    if (!profile || profile.isDeleted === true || profile.isActive === false) {
      return res.status(403).json({ success: false, message: "Account is disabled" });
    }
    if (profile.role === "Staff") {
      return res.status(403).json({ success: false, message: "Admin permission required" });
    }
    req.authProfile = profile;
    return next();
  } catch (error) {
    return res.status(500).json({ success: false, message: "Permission check failed" });
  }
}

app.get("/", (req, res) => {
  res.json({ success: true, message: "StockFlow backend running" });
});

app.get("/health", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    success: true,
    status: "ok",
    firebaseConfigured: Boolean(adminAuth && adminDb),
    environment: process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString()
  });
});

app.get("/ready", async (req, res) => {
  if (!adminDb) {
    return res.status(503).json({
      success: false,
      status: "not-ready",
      message: firebaseInitError?.message || "Firebase is not configured"
    });
  }
  try {
    await adminDb.collection("_health").limit(1).get();
    res.set("Cache-Control", "no-store");
    return res.json({ success: true, status: "ready", timestamp: new Date().toISOString() });
  } catch (error) {
    console.error("Readiness check failed", error);
    return res.status(503).json({ success: false, status: "not-ready" });
  }
});


app.post("/api/staff", requireAuth, requireAdmin, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ success: false, message: "All staff fields are required" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) {
      return res.status(400).json({ success: false, message: "Enter a valid email" });
    }
    if (name.length > 80 || !/^[0-9+\-\s]{7,15}$/.test(phone)) {
      return res.status(400).json({ success: false, message: "Enter a valid name and phone number" });
    }
    if (password.length > 128 || !/^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{8,}$/.test(password)) {
      return res.status(400).json({ success: false, message: "Password does not meet security requirements" });
    }

    const ownerUid = req.authProfile.ownerUid || req.authUser.uid;
    const userRecord = await adminAuth.createUser({ email, password, displayName: name, disabled: false });

    try {
      await adminDb.collection("users").doc(userRecord.uid).set({
        name, phone, email, role: "Staff", ownerUid, adminUid: ownerUid,
        createdBy: req.authUser.uid, isActive: true, isDeleted: false,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      });
    } catch (error) {
      await adminAuth.deleteUser(userRecord.uid).catch(() => {});
      throw error;
    }

    await writeAdminAudit(req, "staff.create", userRecord.uid, { email });
    return res.status(201).json({ success: true, uid: userRecord.uid, message: "Staff account created" });
  } catch (error) {
    console.error("create-staff failed", error);
    if (error?.code === "auth/email-already-exists") {
      return res.status(409).json({ success: false, message: "Email is already registered" });
    }
    return res.status(500).json({ success: false, message: "Unable to create staff account" });
  }
});

app.patch("/api/staff/:uid/status", requireAuth, requireAdmin, async (req, res) => {
  try {
    const targetUid = String(req.params.uid || "").trim();
    const isActive = req.body?.isActive === true;
    const targetProfile = await getProfile(targetUid);
    const ownerUid = req.authProfile.ownerUid || req.authUser.uid;
    if (!targetProfile || targetProfile.role !== "Staff" || targetProfile.ownerUid !== ownerUid) {
      return res.status(404).json({ success: false, message: "Staff user not found" });
    }
    await Promise.all([
      adminAuth.updateUser(targetUid, { disabled: !isActive }),
      adminDb.collection("users").doc(targetUid).update({ isActive, updatedAt: new Date().toISOString(), updatedBy: req.authUser.uid })
    ]);
    await writeAdminAudit(req, isActive ? "staff.enable" : "staff.disable", targetUid);
    return res.json({ success: true, message: isActive ? "Staff enabled" : "Staff disabled" });
  } catch (error) {
    console.error("staff-status failed", error);
    return res.status(500).json({ success: false, message: "Unable to update staff status" });
  }
});

app.delete("/api/firebase/delete-user/:uid", requireAuth, requireAdmin, async (req, res) => {
  try {
    const targetUid = String(req.params.uid || "").trim();
    if (!targetUid || targetUid === req.authUser.uid) {
      return res.status(400).json({ success: false, message: "Invalid target user" });
    }

    const targetProfile = await getProfile(targetUid);
    if (!targetProfile) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const ownerUid = req.authProfile.ownerUid || req.authUser.uid;
    if (targetProfile.role !== "Staff" || targetProfile.ownerUid !== ownerUid) {
      return res.status(403).json({ success: false, message: "You cannot delete this user" });
    }

    await adminAuth.deleteUser(targetUid);
    await adminDb.collection("users").doc(targetUid).delete();
    await writeAdminAudit(req, "staff.delete", targetUid, { email: targetProfile.email || null });

    res.json({ success: true, message: "Staff user deleted" });
  } catch (error) {
    console.error("delete-user failed", error);
    res.status(500).json({ success: false, message: "Unable to delete user" });
  }
});

// Password recovery must use Firebase's signed email reset link from the client.

function encodeCursor(docSnap) {
  return Buffer.from(JSON.stringify({ id: docSnap.id })).toString("base64url");
}
function decodeCursor(value) {
  if (!value) return null;
  try { return JSON.parse(Buffer.from(String(value), "base64url").toString("utf8")); } catch { return null; }
}

async function listOwnedCollection(req, res, collectionName) {
  try {
    const profile = await getProfile(req.authUser.uid);
    if (!profile || profile.isDeleted === true || profile.isActive === false) return res.status(403).json({success:false,message:"Account is disabled"});
    const ownerUid = profile.ownerUid || req.authUser.uid;
    const pageSize = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
    let q = adminDb.collection(collectionName).where("ownerUid", "==", ownerUid).orderBy("__name__").limit(pageSize + 1);
    const cursor = decodeCursor(req.query.cursor);
    if (cursor?.id) { const snap = await adminDb.collection(collectionName).doc(cursor.id).get(); if (snap.exists) q = q.startAfter(snap); }
    const result = await q.get();
    const docs = result.docs.slice(0, pageSize);
    return res.json({success:true,items:docs.map(d=>({id:d.id,...d.data()})),nextCursor:result.docs.length>pageSize?encodeCursor(docs[docs.length-1]):null});
  } catch (error) {
    console.error(`list-${collectionName} failed`, error);
    return res.status(500).json({success:false,message:"Unable to load records"});
  }
}


app.get("/api/system/status", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ownerUid = req.authProfile.ownerUid || req.authUser.uid;
    const [products, orders, users, recentAudit] = await Promise.all([
      adminDb.collection("products").where("ownerUid", "==", ownerUid).count().get(),
      adminDb.collection("orders").where("ownerUid", "==", ownerUid).count().get(),
      adminDb.collection("users").where("ownerUid", "==", ownerUid).count().get(),
      adminDb.collection("adminAuditLogs").where("ownerUid", "==", ownerUid).orderBy("createdAt", "desc").limit(10).get()
    ]);
    res.set("Cache-Control", "no-store");
    return res.json({
      success: true,
      status: "operational",
      counts: {
        products: products.data().count,
        orders: orders.data().count,
        staffProfiles: users.data().count
      },
      recentAdminActions: recentAudit.docs.map((doc) => ({ id: doc.id, ...doc.data() })),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("system-status failed", error);
    return res.status(500).json({ success: false, message: "Unable to load system status" });
  }
});

app.get("/api/products", requireAuth, (req,res)=>listOwnedCollection(req,res,"products"));
app.get("/api/orders", requireAuth, (req,res)=>listOwnedCollection(req,res,"orders"));

app.all("/api/auth/reset-password", (req, res) => {
  res.status(410).json({
    success: false,
    message: "Direct password reset is disabled. Use the secure email reset link."
  });
});

// Public (pre-registration) lookup: does a user with this phone already
// exist? Uses the Admin SDK (bypasses Firestore rules) because this check
// must run BEFORE the caller has an account, so they have no auth token yet.
app.post("/api/auth/check-phone", requireFirebase, async (req, res) => {
  try {
    const phone = String(req.body?.phone || "").trim();
    if (!phone) return res.status(400).json({ success: false, message: "Phone number is required" });
    if (phone.length > 20) return res.status(400).json({ success: false, message: "Invalid phone number" });

    const snap = await adminDb.collection("users").where("phone", "==", phone).limit(5).get();
    const exists = snap.docs.some((doc) => doc.data()?.isDeleted !== true);
    return res.json({ success: true, exists });
  } catch (error) {
    console.error("check-phone failed", error);
    return res.status(500).json({ success: false, message: "Unable to check phone number right now" });
  }
});

// Public (pre-login) lookup: phone -> registered email, for the
// "Find email/username" screen on the login page. No auth required by
// definition (a user recovering their forgotten email can't be logged in
// yet) — uses the Admin SDK so it works regardless of Firestore rules.
app.post("/api/auth/find-email", requireFirebase, async (req, res) => {
  try {
    const phone = String(req.body?.phone || "").trim();
    if (!phone) return res.status(400).json({ success: false, message: "Phone number is required" });
    if (phone.length > 20) return res.status(400).json({ success: false, message: "Invalid phone number" });

    // Single-field filter only (matches how this app queries phone
    // elsewhere) so it works without needing a new Firestore composite index.
    const snap = await adminDb.collection("users")
      .where("phone", "==", phone)
      .limit(5)
      .get();

    const match = snap.docs.find((doc) => doc.data()?.isDeleted !== true);
    if (!match) {
      return res.json({ success: false, message: "No account found with this phone number" });
    }
    const email = match.data()?.email;
    if (!email) {
      return res.json({ success: false, message: "No account found with this phone number" });
    }
    // Poora email kabhi response me nahi bhejte (network tab se bhi dikhta). Sirf masked: ab****@domain.com
    return res.json({ success: true, email: maskEmailAddress(email) });
  } catch (error) {
    console.error("find-email failed", error);
    return res.status(500).json({ success: false, message: "Unable to search right now" });
  }
});


/* ------------------------------------------------------------------
   SERVER-SIDE REGISTRATION (email OTP)
   OTP ab backend generate + verify karta hai (pehle browser me hota tha, jise koi bhi bypass kar sakta tha).
   Firestore rules me client se `users` create band hai, isliye account sirf is route se ban sakta hai.
------------------------------------------------------------------- */
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_RESEND_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const PASSWORD_RULE = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{8,}$/;
const EMAIL_RULE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RULE = /^[0-9+\-\s]{7,15}$/;

const otpSecret = String(process.env.OTP_SECRET || "").trim() || (isProduction ? "" : "dev-only-otp-secret");
const emailjsCfg = {
  serviceId: String(process.env.EMAILJS_SERVICE_ID || "service_15yzwik").trim(),
  templateId: String(process.env.EMAILJS_TEMPLATE_ID || "template_b81ib1p").trim(),
  publicKey: String(process.env.EMAILJS_PUBLIC_KEY || "zGYs_PtqgASVdf11P").trim(),
  privateKey: String(process.env.EMAILJS_PRIVATE_KEY || "").trim()
};

const brevoCfg = {
  apiKey: String(process.env.BREVO_API_KEY || "").trim(),
  senderEmail: String(process.env.BREVO_SENDER_EMAIL || "").trim(),
  senderName: String(process.env.BREVO_SENDER_NAME || "StockFlow Pro").trim()
};
// Provider: BREVO_API_KEY set ho to Brevo (free 300/day), warna EmailJS
const otpEmailConfigured = () => Boolean(otpSecret && ((brevoCfg.apiKey && brevoCfg.senderEmail) || emailjsCfg.privateKey));

function escapeHtmlText(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
}

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many attempts. Please try again after some time." }
});
app.use("/api/auth/send-otp", registerLimiter);
app.use("/api/auth/register", registerLimiter);

function otpDocRef(email) {
  const id = crypto.createHash("sha256").update(email).digest("hex");
  return adminDb.collection("registrationOtps").doc(id);
}
function hashOtp(email, otp) {
  return crypto.createHmac("sha256", otpSecret).update(`${email}:${otp}`).digest("hex");
}
function safeEqualHex(a, b) {
  const x = Buffer.from(String(a), "hex");
  const y = Buffer.from(String(b), "hex");
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function cleanText(value, max) {
  return String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}
async function sendOtpViaBrevo(name, email, otp) {
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": brevoCfg.apiKey, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      sender: { name: brevoCfg.senderName, email: brevoCfg.senderEmail },
      to: [{ email, name }],
      subject: "Your StockFlow Pro verification code",
      htmlContent:
        `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px">` +
        `<h2 style="margin:0 0 12px">StockFlow Pro</h2>` +
        `<p>Hi ${escapeHtmlText(name)},</p>` +
        `<p>Your verification code is:</p>` +
        `<p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:16px 0">${otp}</p>` +
        `<p>This code is valid for 10 minutes. If you did not request it, you can ignore this email.</p></div>`
    })
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Brevo ${response.status}: ${detail.slice(0, 200)}`);
  }
}

async function sendOtpEmail(name, email, otp) {
  if (brevoCfg.apiKey && brevoCfg.senderEmail) return sendOtpViaBrevo(name, email, otp);
  const response = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service_id: emailjsCfg.serviceId,
      template_id: emailjsCfg.templateId,
      user_id: emailjsCfg.publicKey,
      accessToken: emailjsCfg.privateKey,
      template_params: { name, otp, to_email: email }
    })
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`EmailJS ${response.status}: ${detail.slice(0, 200)}`);
  }
}
function maskEmailAddress(email) {
  const [local = "", domain = ""] = String(email).split("@");
  return `${local.slice(0, 2)}****@${domain}`;
}
async function phoneAlreadyUsed(phone) {
  const snap = await adminDb.collection("users").where("phone", "==", phone).limit(5).get();
  return snap.docs.some((doc) => doc.data()?.isDeleted !== true);
}

app.post("/api/auth/send-otp", requireFirebase, async (req, res) => {
  try {
    if (!otpEmailConfigured()) {
      console.error("Registration email is not configured (set OTP_SECRET + BREVO_API_KEY/BREVO_SENDER_EMAIL or EMAILJS_PRIVATE_KEY)");
      return res.status(503).json({ success: false, message: "Registration is temporarily unavailable" });
    }
    const name = cleanText(req.body?.name, 80);
    const phone = cleanText(req.body?.phone, 20);
    const email = cleanText(req.body?.email, 120).toLowerCase();

    if (!name || !phone || !email) return res.status(400).json({ success: false, message: "Name, phone and email are required" });
    if (!EMAIL_RULE.test(email)) return res.status(400).json({ success: false, message: "Enter a valid email" });
    if (!PHONE_RULE.test(phone)) return res.status(400).json({ success: false, message: "Enter a valid phone number" });

    if (await adminAuth.getUserByEmail(email).then(() => true).catch(() => false)) {
      return res.status(409).json({ success: false, message: "Email is already registered" });
    }
    if (await phoneAlreadyUsed(phone)) {
      return res.status(409).json({ success: false, message: "Phone number already registered" });
    }

    const ref = otpDocRef(email);
    const existing = await ref.get();
    const now = Date.now();
    if (existing.exists && now - Number(existing.data().lastSentAt || 0) < OTP_RESEND_MS) {
      return res.status(429).json({ success: false, message: "Please wait a minute before requesting another OTP" });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    await ref.set({ email, otpHash: hashOtp(email, otp), expiresAt: now + OTP_TTL_MS, attempts: 0, lastSentAt: now, createdAt: now });

    try {
      await sendOtpEmail(name, email, otp);
    } catch (error) {
      await ref.delete().catch(() => {});
      console.error("send-otp email failed", error.message);
      return res.status(502).json({ success: false, message: "Failed to send OTP. Please try again" });
    }
    return res.json({ success: true, message: "OTP sent to your email" });
  } catch (error) {
    console.error("send-otp failed", error);
    return res.status(500).json({ success: false, message: "Unable to send OTP right now" });
  }
});

app.post("/api/auth/register", requireFirebase, async (req, res) => {
  try {
    if (!otpSecret) return res.status(503).json({ success: false, message: "Registration is temporarily unavailable" });
    const name = cleanText(req.body?.name, 80);
    const phone = cleanText(req.body?.phone, 20);
    const email = cleanText(req.body?.email, 120).toLowerCase();
    const password = String(req.body?.password || "");
    const otp = String(req.body?.otp || "").trim();

    if (!name || !phone || !email || !password || !otp) return res.status(400).json({ success: false, message: "All fields are required" });
    if (!EMAIL_RULE.test(email)) return res.status(400).json({ success: false, message: "Enter a valid email" });
    if (!PHONE_RULE.test(phone)) return res.status(400).json({ success: false, message: "Enter a valid phone number" });
    if (!PASSWORD_RULE.test(password) || password.length > 128) return res.status(400).json({ success: false, message: "Password does not meet security requirements" });
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ success: false, message: "Invalid OTP" });

    const ref = otpDocRef(email);
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ success: false, message: "OTP expired. Please request a new one" });
    const record = snap.data();
    if (Date.now() > Number(record.expiresAt || 0)) {
      await ref.delete().catch(() => {});
      return res.status(400).json({ success: false, message: "OTP expired. Please request a new one" });
    }
    if (Number(record.attempts || 0) >= OTP_MAX_ATTEMPTS) {
      await ref.delete().catch(() => {});
      return res.status(429).json({ success: false, message: "Too many wrong attempts. Please request a new OTP" });
    }
    if (!safeEqualHex(record.otpHash, hashOtp(email, otp))) {
      await ref.update({ attempts: FieldValue.increment(1) }).catch(() => {});
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    await ref.delete().catch(() => {});

    if (await phoneAlreadyUsed(phone)) return res.status(409).json({ success: false, message: "Phone number already registered" });

    let userRecord;
    try {
      userRecord = await adminAuth.createUser({ email, password, displayName: name, emailVerified: true, disabled: false });
    } catch (error) {
      if (error?.code === "auth/email-already-exists") return res.status(409).json({ success: false, message: "Email is already registered" });
      throw error;
    }

    try {
      const stamp = new Date().toISOString();
      await adminDb.collection("users").doc(userRecord.uid).set({
        name, phone, email, role: "Admin", ownerUid: userRecord.uid, adminUid: userRecord.uid, createdBy: userRecord.uid,
        isActive: true, isDeleted: false, createdAt: stamp, updatedAt: stamp
      });
    } catch (error) {
      await adminAuth.deleteUser(userRecord.uid).catch(() => {});
      throw error;
    }
    return res.status(201).json({ success: true, message: "Account created successfully" });
  } catch (error) {
    console.error("register failed", error);
    return res.status(500).json({ success: false, message: "Unable to create account right now" });
  }
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: "Not found" });
});

app.use((error, req, res, next) => {
  if (error && error.type === "entity.parse.failed") {
    return res.status(400).json({ success: false, message: "Invalid JSON body" });
  }
  if (error && error.message === "Origin not allowed by CORS") {
    return res.status(403).json({ success: false, message: "Origin not allowed" });
  }
  console.error("Unhandled error", error);
  return res.status(500).json({ success: false, message: "Internal server error" });
});

const PORT = Number(process.env.PORT) || 5000;
const server = app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

function shutdown(signal) {
  console.log(`${signal} received; closing HTTP server`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
