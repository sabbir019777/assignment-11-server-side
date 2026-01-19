const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const helmet = require("helmet");

require("dotenv").config();
const multer = require("multer");
const path = require("path");
const axios = require("axios");

const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.VITE_APP_CLIENT_URL || "http://localhost:5173";
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;

const app = express();

// Helmet
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use((req, res, next) => {
  if (req.originalUrl === "/webhook/payment") {
    next();
  } else {
    express.json({ limit: "10mb" })(req, res, next);
  }
});

// CORS configuration
const corsOptions = {
  origin: [
    "https://digital-lifes-lesson.netlify.app",
    "https://assignment-11-server-side-swart.vercel.app", 
    "http://localhost:5173",
    "http://localhost:5000"
  ],
  credentials: true,
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));

// --- static uploads folder 
const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir));

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post("/upload/image", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send({ message: "No image uploaded." });

    const imageBase64 = req.file.buffer.toString("base64");
    const formData = new URLSearchParams();
    formData.append("image", imageBase64);

    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
      formData
    );

    return res.status(201).send({ url: response.data.data.url });
  } catch (error) {
    console.error("Upload failed:", error.message);
    return res.status(500).send({ message: "Failed to upload image to cloud." });
  }
});

// Firebase Init
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (!admin.apps.length) {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    }
    console.log("✅ Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT env var");
  } else {
    try {
      const localServiceAccount = require(path.join(
        __dirname,
        "digital-life-lesson-firebase-adminsdk.json"
      ));
      if (localServiceAccount && !admin.apps.length) {
        admin.initializeApp({
          credential: admin.credential.cert(localServiceAccount),
        });
        console.log("✅ Firebase Admin initialized from local service account file");
      }
    } catch (err) {}
  }
} catch (error) {
  console.error("Firebase Admin init failed:", error);
}

// Payment Webhook
app.post(
  "/webhook/payment",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const event = JSON.parse(req.body.toString());
      if (
        event.type === "checkout.session.completed" ||
        event.status === "completed"
      ) {
        const paymentInfo = event.data.object;
        const userUid = paymentInfo.metadata?.userId || paymentInfo.userId;
        if (!userUid)
          return res.status(400).send({ message: "Missing user ID." });

        await usersCollection.updateOne(
          { uid: userUid },
          { $set: { isPremium: true, updatedAt: new Date() } }
        );
        await paymentsCollection.insertOne({
          ...paymentInfo,
          userId: userUid,
          status: "completed",
          isRefunded: false,
          createdAt: new Date(),
        });

        console.log(`✅User ${userUid} upgraded to Premium.`);
        return res.status(200).send({ received: true });
      }
    } catch (error) {
      console.error("Webhook failed:", error);
      return res.status(500).send({ message: "Webhook failed." });
    }
    res.status(200).send({ received: true });
  }
);

// MongoDB connection
const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db, usersCollection, lessonsCollection, commentsCollection, lessonsReportsCollection, likesCollection, paymentsCollection, favouritesCollection;

async function connectDB() {
  if (db) return; 
  try {
    await client.connect();
    db = client.db("lifelessons");
    usersCollection = db.collection("users");
    lessonsCollection = db.collection("lessons");
    commentsCollection = db.collection("comments");
    lessonsReportsCollection = db.collection("lessonsreports");
    likesCollection = db.collection("likes");
    paymentsCollection = db.collection("payments");
    favouritesCollection = db.collection("favourites");
    console.log("✅ MongoDB connected successfully");
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error);
  }
}

app.use(async (req, res, next) => {
  await connectDB(); 
  next();
});

// Middlewares
const verifyJWT = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized: Token required" });
  }
  const token = auth.split(" ")[1];
  try {
    let decodedData = null;
    if (typeof admin !== "undefined" && admin?.auth) {
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        decodedData = { email: decoded.email, uid: decoded.uid || decoded.sub };
      } catch (fbErr) {}
    }
    if (!decodedData) {
      const secret = process.env.JWT_SECRET || process.env.ACCESS_TOKEN_SECRET;
      if (!secret) return res.status(500).send({ message: "JWT Secret missing in Server Environment." });
      const decoded = jwt.verify(token, secret);
      decodedData = { email: decoded.email, uid: decoded.uid };
    }
    req.decoded = decodedData;
    req.userEmail = decodedData.email;
    req.userUid = decodedData.uid;
    next();
  } catch (error) {
    console.error("JWT Verification Failed:", error.message);
    return res.status(403).send({ message: "Invalid or expired token" });
  }
};

const verifyAdmin = async (req, res, next) => {
  const email = req.decoded?.email;
  const masterAdminEmail = "admins@gmail.com"; 
  if (!email) return res.status(401).send({ message: "Unauthorized: Email not found" });
  try {
    const user = await usersCollection.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const isAdmin = (user && user.role === "admin") || email.toLowerCase() === masterAdminEmail.toLowerCase();
    if (!isAdmin) return res.status(403).send({ message: "Forbidden Access" });
    next();
  } catch (error) {
    res.status(500).send({ message: "Internal Server Error" });
  }
};

// --- ROUTES ---

// ==========================================
// 🔥 ADMIN FIXED ROUTES (RESOLVED & DELETE) 🔥
// ==========================================

// 1. RESOLVE REPORT (Fix for Resolved Button)
app.delete("/admin/reports/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    // Database check to delete report
    const result = await lessonsReportsCollection.deleteOne({ _id: new ObjectId(id) });
    console.log("Deleted Report ID:", id); 
    res.send(result);
  } catch (error) {
    console.error("Error resolving report:", error);
    res.status(500).send({ message: "Failed to resolve report" });
  }
});

// 2. ADMIN DELETE LESSON (Fix for Delete Button)
app.delete("/admin/lessons/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    // Database check to delete lesson
    const result = await lessonsCollection.deleteOne({ _id: new ObjectId(id) });
    console.log("Deleted Lesson ID:", id);
    res.send(result);
  } catch (error) {
    console.error("Error deleting lesson:", error);
    res.status(500).send({ message: "Failed to delete lesson" });
  }
});

// 3. ADMIN FEATURE TOGGLE
app.patch("/admin/lessons/featured/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { ...req.body } };
    const result = await lessonsCollection.updateOne(filter, updateDoc);
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to feature lesson" });
  }
});

// ==========================================

app.get("/users/status", verifyJWT, async (req, res) => {
  try {
    const uid = req.userUid;
    const user = await usersCollection.findOne({ uid });
    if (!user) return res.status(404).send({ message: "User not found." });
    res.status(200).send({
      uid: user.uid,
      email: user.email,
      name: user.name,
      photoURL: user.photoURL || "",
      isPremium: Boolean(user.isPremium),
      role: user.role || "user",
      upgradedAt: user.upgradedAt,
      totalLessonsCreated: user.totalLessonsCreated || 0,
    });
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch status." });
  }
});

app.patch("/lessons/:id/toggle-favorite", verifyJWT, async (req, res) => {
  const lessonId = req.params.id;
  const uid = req.userUid;
  if (!ObjectId.isValid(lessonId)) return res.status(400).send({ message: "Invalid ID." });
  try {
    const query = { userId: uid, lessonId: lessonId };
    const existing = await favouritesCollection.findOne(query);
    if (existing) {
      await favouritesCollection.deleteOne({ _id: existing._id });
      await lessonsCollection.updateOne({ _id: new ObjectId(lessonId) }, { $inc: { favoritesCount: -1 } });
      return res.send({ success: true, message: "Removed", isFavorite: false });
    } else {
      await favouritesCollection.insertOne({ ...query, createdAt: new Date() });
      await lessonsCollection.updateOne({ _id: new ObjectId(lessonId) }, { $inc: { favoritesCount: 1 } });
      return res.send({ success: true, message: "Added", isFavorite: true });
    }
  } catch (error) {
    res.status(500).send({ message: "Server Error" });
  }
});

app.post("/users", async (req, res) => {
  const user = req.body;
  if (!user.uid || !user.email) return res.status(400).send({ message: "Missing required fields." });
  const existingUser = await usersCollection.findOne({ uid: user.uid });
  const now = new Date();
  if (existingUser) {
    await usersCollection.updateOne({ uid: user.uid }, { $set: { lastLogin: now, name: user.name, photoURL: user.photoURL, email: user.email } });
    return res.status(200).send({ message: "User data synchronized.", user: existingUser });
  }
  const newUser = { uid: user.uid, email: user.email, name: user.name || "Anonymous User", photoURL: user.photoURL || "", role: "user", isPremium: false, totalLessonsCreated: 0, createdAt: now, lastLogin: now };
  const result = await usersCollection.insertOne(newUser);
  res.status(201).send({ message: "New user created.", insertedId: result.insertedId });
});

app.post("/users/upgrade", verifyJWT, async (req, res) => {
  try {
    const uid = req.userUid;
    const updateResult = await usersCollection.findOneAndUpdate({ uid }, { $set: { isPremium: true, upgradedAt: new Date() } }, { returnDocument: "after", upsert: true });
    const updatedUser = updateResult.value || updateResult;
    return res.status(200).send({ message: "Upgraded", user: updatedUser });
  } catch (error) {
    return res.status(500).send({ message: "Failed" });
  }
});

app.get("/users/top-contributors", async (req, res) => {
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    let contributors = await lessonsCollection.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      { $group: { _id: "$creatorId", weeklyLessons: { $sum: 1 } } },
      { $lookup: { from: "users", localField: "_id", foreignField: "uid", as: "userInfo" } },
      { $unwind: "$userInfo" },
      { $project: { _id: 0, uid: "$_id", weeklyLessons: 1, name: "$userInfo.name", photoURL: "$userInfo.photoURL" } },
      { $sort: { weeklyLessons: -1 } },
      { $limit: 5 }
    ]).toArray();
    res.status(200).send(contributors);
  } catch (error) {
    res.status(500).send({ message: "Error fetching top contributors", error: error.message });
  }
});

app.get("/lessons/featured", async (req, res) => {
  try {
    const featured = await lessonsCollection.find({}).sort({ createdAt: -1 }).limit(8).toArray();
    res.status(200).send(featured);
  } catch (error) {
    res.status(500).send({ message: "Error fetching featured lessons", error: error.message });
  }
});

app.get("/lessons/most-saved", async (req, res) => {
  try {
    const mostSaved = await lessonsCollection.find({ isReviewed: true }).sort({ favoritesCount: -1, createdAt: -1 }).limit(10).toArray();
    res.status(200).send(mostSaved);
  } catch (error) {
    res.status(500).send({ message: "Error fetching most saved lessons", error: error.message });
  }
});

app.get("/lessons/public", async (req, res) => {
  try {
    const publicLessons = await lessonsCollection.find({ visibility: "public", isReviewed: true }).sort({ createdAt: -1 }).limit(12).toArray();
    res.send(publicLessons);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.post("/lessons", verifyJWT, async (req, res) => {
  const newLesson = req.body;
  if (!newLesson.title || !newLesson.creatorId) return res.status(400).send({ message: "Missing fields" });
  try {
    const lessonToInsert = { ...newLesson, likesCount: 0, favoritesCount: 0, viewsCount: 0, reportedCount: 0, isReviewed: true, createdAt: new Date() };
    const result = await lessonsCollection.insertOne(lessonToInsert);
    await usersCollection.updateOne({ uid: req.userUid }, { $inc: { totalLessonsCreated: 1 } });
    res.status(201).send({ insertedId: result.insertedId });
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.get("/lessons/my-lessons/:uid", verifyJWT, async (req, res) => {
  try {
    const uid = req.params.uid;
    const query = { creatorId: uid };
    const result = await lessonsCollection.find(query).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch my lessons" });
  }
});

// User Delete My Lesson
app.patch("/lessons/delete-my-lesson/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await lessonsCollection.deleteOne(query);
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to delete lesson" });
  }
});

// ADD REPORT 
app.post("/lessons/report", verifyJWT, async (req, res) => {
  try {
    const report = req.body;
    const result = await lessonsReportsCollection.insertOne({ ...report, createdAt: new Date() });
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to submit report" });
  }
});

// GET ALL REPORTS 
app.get("/admin/reports", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const reports = await lessonsReportsCollection.find().toArray();
    res.send(reports);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch reports" });
  }
});

app.get("/lessons/:id", async (req, res) => {
  try {
    const lessonId = req.params.id;
    if (!ObjectId.isValid(lessonId)) return res.status(400).send({ message: "Invalid ID" });
    const lesson = await lessonsCollection.findOne({ _id: new ObjectId(lessonId) });
    if (!lesson) return res.status(404).send({ message: "Not found" });
    await lessonsCollection.updateOne({ _id: new ObjectId(lessonId) }, { $inc: { viewsCount: 1 } });
    res.send(lesson);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.get("/lessons/:id/similar", async (req, res) => {
  try {
    const lessonId = req.params.id;
    const category = req.query.category;
    const filter = { _id: { $ne: new ObjectId(lessonId) }, ...(category && { category }), isPremium: false };
    const similar = await lessonsCollection.find(filter).limit(5).toArray();
    res.send(similar);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.get("/comments/:lessonId", async (req, res) => {
  try {
    const comments = await commentsCollection.find({ lessonId: req.params.lessonId }).sort({ createdAt: -1 }).toArray();
    res.send(comments);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.post("/comments", verifyJWT, async (req, res) => {
  try {
    const newComment = { ...req.body, createdAt: new Date() };
    const result = await commentsCollection.insertOne(newComment);
    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.patch("/lessons/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const requester = await usersCollection.findOne({ uid: req.userUid });
    
    if (requester?.role !== 'admin') {
       filter.creatorId = req.userUid;
    }
    const result = await lessonsCollection.updateOne(filter, { $set: { ...req.body, updatedAt: new Date() } });
    
    if (result.matchedCount === 0) {
      return res.status(403).send({ message: "Unauthorized or Lesson not found" });
    }
    
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.get("/api/lessons/favorites/:uid", verifyJWT, async (req, res) => {
  try {
    const uid = req.params.uid;
    const favorites = await favouritesCollection.find({ userId: uid }).toArray();
    if (!favorites || favorites.length === 0) return res.send([]);
    const lessonIds = favorites.map(fav => new ObjectId(fav.lessonId));
    const favoriteLessons = await lessonsCollection.find({ _id: { $in: lessonIds } }).toArray();
    res.send(favoriteLessons);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch favorite lessons" });
  }
});

app.get("/api/users/my-stats", verifyJWT, async (req, res) => {
  try {
    const totalFavorites = await favouritesCollection.countDocuments({ userId: req.userUid });
    res.send({ totalLessonsTaken: totalFavorites, vocabLearned: totalFavorites * 5 });
  } catch (error) {
    res.status(500).send({ message: "Failed" });
  }
});

app.get("/users/all", verifyJWT, verifyAdmin, async (req, res) => {
  const users = await usersCollection.find().toArray();
  res.send(users);
});

app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
  await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
  res.send({ success: true });
});

app.get("/admin/lessons", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const lessons = await lessonsCollection.find().toArray();
    res.send(lessons);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch all lessons" });
  }
});

app.post("/lessons/:id/like", verifyJWT, async (req, res) => {
  const lessonId = req.params.id;
  const userEmail = req.userEmail;
  const lesson = await lessonsCollection.findOne({ _id: new ObjectId(lessonId) });
  const hasLiked = (lesson.likedBy || []).includes(userEmail);
  const update = hasLiked ? { $pull: { likedBy: userEmail }, $inc: { likesCount: -1 } } : { $addToSet: { likedBy: userEmail }, $inc: { likesCount: 1 } };
  await lessonsCollection.updateOne({ _id: new ObjectId(lessonId) }, update);
  res.send({ success: true, isLiked: !hasLiked });
});

app.get("/", (req, res) => res.send("✅ Digital Life Lessons Full API Running"));

module.exports = app; 

if (process.env.NODE_ENV !== 'production') {
  connectDB().then(() => {
    app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  });
}