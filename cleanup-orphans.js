/* Orphan Auth accounts cleanup
   Firebase ki public API key se koi bhi bina profile wala Auth account bana sakta hai (spam).
   Aise accounts kuch access nahi kar sakte, lekin ye script unhe delete kar deti hai:
   "users/{uid}" profile NAHI hai aur account 24 ghante se purana hai.
   Chalane ka tarika: npm run cleanup   (DRY_RUN=1 npm run cleanup  -> sirf dikhata hai, delete nahi karta) */
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const { initializeApp, cert, applicationDefault } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

const MIN_AGE_MS = 24 * 60 * 60 * 1000;
const dryRun = process.env.DRY_RUN === "1";

function credential() {
  if (String(process.env.FIREBASE_SERVICE_ACCOUNT || "").trim()) {
    return cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT));
  }
  const file = fs.readdirSync(__dirname).find((n) => n.toLowerCase() === "serviceaccountkey.json");
  if (file) return cert(JSON.parse(fs.readFileSync(path.join(__dirname, file), "utf8")));
  return applicationDefault();
}

(async () => {
  initializeApp({ credential: credential() });
  const auth = getAuth();
  const db = getFirestore();
  let pageToken;
  let scanned = 0;
  let removed = 0;

  do {
    const page = await auth.listUsers(1000, pageToken);
    pageToken = page.pageToken;
    scanned += page.users.length;

    const old = page.users.filter((u) => Date.now() - new Date(u.metadata.creationTime).getTime() > MIN_AGE_MS);
    if (!old.length) continue;

    const refs = old.map((u) => db.collection("users").doc(u.uid));
    const snaps = await db.getAll(...refs);
    const orphans = old.filter((_, i) => !snaps[i].exists);

    for (const user of orphans) {
      console.log(`${dryRun ? "[dry-run] would delete" : "deleting"} orphan ${user.uid} (${user.email || "no email"})`);
      if (!dryRun) await auth.deleteUser(user.uid);
      removed++;
    }
  } while (pageToken);

  console.log(`Done. scanned=${scanned} orphans=${removed} dryRun=${dryRun}`);
})().catch((error) => {
  console.error("Cleanup failed:", error.message);
  process.exit(1);
});
