// server.js
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
const SERVER_BASE_URL =
  process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;

const app = express();

// Helmet with disabled CORS 

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

// Webhook-এর জন্য Raw Body দরকার

app.use((req, res, next) => {
  if (req.originalUrl === "/webhook/payment") {
    next();
  } else {
    express.json({ limit: "10mb" })(req, res, next);
  }
});

// CORS configuration

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (origin === CLIENT_URL) return callback(null, true);

    if (origin.match(/^http:\/\/localhost:\d+$/)) return callback(null, true);

    callback(new Error("CORS not allowed"));
  },
  credentials: true,
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

// Additional middleware to ensure CORS headers are sent for all responses including static files

app.use((req, res, next) => {
  const origin = req.get("origin");

  if (!origin) {
    res.header("Access-Control-Allow-Origin", "*");
  } else if (
    origin === CLIENT_URL ||
    origin.match(/^http:\/\/localhost:\d+$/)
  ) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header(
    "Access-Control-Allow-Methods",
    "GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS"
  );
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// --- static uploads folder (for simple local image storage) ---

const uploadsDir = path.join(__dirname, "uploads");
app.use("/uploads", express.static(uploadsDir));



// upload/image

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post("/upload/image", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send({ message: "No image uploaded." });

    // ইমেজকে Base64 এ কনভার্ট করা
    const imageBase64 = req.file.buffer.toString("base64");
    const formData = new URLSearchParams();
    formData.append("image", imageBase64);

    // ImgBB API তে পাঠানো
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

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log(
      "✅ Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT env var"
    );
  } else {
    try {
      const localServiceAccount = require(path.join(
        __dirname,
        "digital-life-lesson-firebase-adminsdk.json"
      ));
      if (localServiceAccount) {
        admin.initializeApp({
          credential: admin.credential.cert(localServiceAccount),
        });
        console.log(
          "✅ Firebase Admin initialized from local service account file"
        );
      }
    } catch (err) {}
  }
} catch (error) {
  console.error("Firebase Admin init failed:", error);
}




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

let usersCollection,
  lessonsCollection,
  commentsCollection,
  lessonsReportsCollection,
  likesCollection,
  paymentsCollection,
  favouritesCollection;

async function connectDB() {
  try {
    await client.connect();
    const db = client.db("lifelessons");
    usersCollection = db.collection("users");
    lessonsCollection = db.collection("lessons");
    commentsCollection = db.collection("comments");
    lessonsReportsCollection = db.collection("lessonsreports");
    likesCollection = db.collection("likes");
    paymentsCollection = db.collection("payments");
    favouritesCollection = db.collection("favourites");
    console.log("✅ MongoDB connected (lifelessons)");
  } catch (error) {
    console.error("MongoDB connection failed:", error);
    process.exit(1);
  }
}
connectDB();

// --------------------
// Middlewares
// --------------------

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
      if (!secret)
        return res
          .status(500)
          .send({ message: "JWT Secret missing in Server Environment." });

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

//  [২. verifyAdmin Middleware] 

const verifyAdmin = async (req, res, next) => {
  const email = req.decoded?.email;

  const masterAdminEmail = "admins@gmail.com";

  if (!email) {
    return res.status(401).send({ message: "Unauthorized: Email not found" });
  }

  try {
    const user = await usersCollection.findOne({ email: email });

    const isAdmin =
      user?.role === "admin" ||
      email.toLowerCase() === masterAdminEmail.toLowerCase();

    if (!isAdmin) {
      console.log(`❌ Access Denied for: ${email}`);
      return res.status(403).send({ message: "forbidden access" });
    }

    console.log(`✅ Admin Access Granted for: ${email}`);
    next();
  } catch (error) {
    console.error("Admin Verification Error:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
};

// 1. User Registrations



// 2. Check User Statues

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

// 11. Toggle Favourite

app.patch("/lessons/:id/toggle-favorite", verifyJWT, async (req, res) => {
  const lessonId = req.params.id;
  const uid = req.userUid;

  if (!ObjectId.isValid(lessonId))
    return res.status(400).send({ message: "Invalid ID." });

  try {
    const query = { userId: uid, lessonId: lessonId };
    const existing = await favouritesCollection.findOne(query);

    if (existing) {
      await favouritesCollection.deleteOne({ _id: existing._id });
      await lessonsCollection.updateOne(
        { _id: new ObjectId(lessonId) },
        { $inc: { favoritesCount: -1 } }
      );
      return res.send({ success: true, message: "Removed", isFavorite: false });
    } else {
      await favouritesCollection.insertOne({ ...query, createdAt: new Date() });
      await lessonsCollection.updateOne(
        { _id: new ObjectId(lessonId) },
        { $inc: { favoritesCount: 1 } }
      );
      return res.send({ success: true, message: "Added", isFavorite: true });
    }
  } catch (error) {
    res.status(500).send({ message: "Server Error" });
  }
});



// ROUTES


app.post("/users", async (req, res) => {
  const user = req.body;
  if (!user.uid || !user.email)
    return res
      .status(400)
      .send({ message: "Missing required fields: uid or email." });

  const existingUser = await usersCollection.findOne({ uid: user.uid });
  const now = new Date();

  if (existingUser) {
    await usersCollection.updateOne(
      { uid: user.uid },
      {
        $set: {
          lastLogin: now,
          name: user.name,
          photoURL: user.photoURL,
          email: user.email,
        },
      }
    );
    return res
      .status(200)
      .send({ message: "User data synchronized.", user: existingUser });
  }

  const newUser = {
    uid: user.uid,
    email: user.email,
    name: user.name || "Anonymous User",
    photoURL: user.photoURL || "",
    role: "user",
    isPremium: false,
    totalLessonsCreated: 0,
    createdAt: now,
    lastLogin: now,
  };

  const result = await usersCollection.insertOne(newUser);
  res
    .status(201)
    .send({ message: "New user created.", insertedId: result.insertedId });
});


// Upgrade user to premium 

app.post("/users/upgrade", verifyJWT, async (req, res) => {
  try {
    const uid = req.userUid;
    if (!uid) {
      console.warn("❌ Upgrade attempt without UID");
      return res.status(401).send({ message: "Unauthorized" });
    }

    console.log("🔄 Processing upgrade for UID:", uid);

    const updateResult = await usersCollection.findOneAndUpdate(
      { uid },
      { $set: { isPremium: true, upgradedAt: new Date() } },
      { returnDocument: "after", upsert: true }
    );

    const updatedUser = updateResult.value || updateResult;

    if (!updatedUser) {
      console.error("❌ Update returned no user document");
      return res.status(500).send({ message: "Failed to update user." });
    }

    // Return consistent response with essential user fields

    const responseUser = {
      uid: updatedUser.uid,
      email: updatedUser.email,
      name: updatedUser.name || updatedUser.displayName,
      photoURL: updatedUser.photoURL || "",
      isPremium: true,
      role: updatedUser.role || "user",
      upgradedAt: updatedUser.upgradedAt,
      totalLessonsCreated: updatedUser.totalLessonsCreated || 0,
    };

    console.log("✅ User upgraded to premium:", uid);
    return res.status(200).send({
      message: "Upgraded to premium successfully",
      user: responseUser,
    });
  } catch (error) {
    console.error("❌ Failed to upgrade user:", error.message || error);
    return res.status(500).send({
      message: "Failed to upgrade user. Please try again.",
      error: error.message,
    });
  }
});

// 3. Top Contributors 

app.get("/users/top-contributors", async (req, res) => {
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    let contributors = await lessonsCollection
      .aggregate([
        {
          $match: {
            createdAt: { $gte: sevenDaysAgo },
          },
        },
        {
          $group: {
            _id: "$creatorId",
            weeklyLessons: { $sum: 1 },
          },
        },
        {
          $lookup: {
            from: "users",
            localField: "_id",
            foreignField: "uid",
            as: "userInfo",
          },
        },
        { $unwind: "$userInfo" },
        {
          $project: {
            _id: 0,
            uid: "$_id",
            weeklyLessons: 1,
            name: { $ifNull: ["$userInfo.name", "$userInfo.displayName"] },
            photoURL: { $ifNull: ["$userInfo.photoURL", "$userInfo.photo"] },
          },
        },
        { $sort: { weeklyLessons: -1 } },
        { $limit: 5 },
      ])
      .toArray();

    if (contributors.length < 5) {
      const additionalUsers = await usersCollection
        .find({ uid: { $nin: contributors.map((c) => c.uid) } })
        .limit(5 - contributors.length)
        .toArray();

      const extraData = additionalUsers.map((u) => ({
        uid: u.uid,
        weeklyLessons: 0,
        name: u.name || u.displayName || "Anonymous User",
        photoURL: u.photoURL || u.photo || "",
      }));

      contributors = [...contributors, ...extraData];
    }

    console.log("Final contributors count to send:", contributors.length);
    res.send(contributors);
  } catch (error) {
    console.error("Aggregation Error:", error);
    res.status(500).send({ message: "Error", error: error.message });
  }
});

// 4. Featured Lessonss

app.get("/lessons/featured", async (req, res) => {
  try {
    const featured = await lessonsCollection
      .find({
        isFeatured: true,
        isReviewed: true,
        visibility: "public",
      })
      .sort({ _id: 1 })
      .skip(56)
      .limit(6)
      .toArray();

    res.send(featured);
  } catch (error) {
    res.status(500).send({ message: "Error fetching data" });
  }
});

// 5. Most Saved Lessonss

app.get("/lessons/most-saved", async (req, res) => {
  try {
    const mostSaved = await lessonsCollection
      .find({ isReviewed: true })
      .sort({
        favoritesCount: -1,
        createdAt: -1,
      })
      .skip(82)
      .limit(10)
      .toArray();

    res.send(mostSaved);
  } catch (error) {
    console.error("Most Saved Fetch Error:", error);
    res.status(500).send({ message: "Failed to fetch most saved lessons" });
  }
});

// 6. Public Lessonss

app.get("/lessons/public", async (req, res) => {
  try {
    const publicLessons = await lessonsCollection
      .find({
        visibility: "public",
        isReviewed: true,
      })
      .sort({ createdAt: -1 })
      .limit(12)
      .toArray();

    res.send(publicLessons);
  } catch (error) {
    console.error("Public Lessons Fetch Error:", error);
    res.status(500).send({ message: "Failed to fetch public lessons" });
  }
});


// 7. Create Lessons

app.post("/lessons", verifyJWT, async (req, res) => {
  const user = await usersCollection.findOne({ uid: req.userUid });
  const isPremiumLesson = req.body.accessLevel === "Premium";
  const newLesson = req.body;
  if (!newLesson.title || !newLesson.description || !newLesson.creatorId) {
    return res.status(400).send({ message: "Missing required fields." });
  }

  try {
    const lessonToInsert = {
      ...newLesson,
      creatorEmail: req.userEmail,
      isPremium: isPremiumLesson,
      likesCount: 0,
      favoritesCount: 0,
      viewsCount: 0,
      reportedCount: 0,
      isReviewed: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await lessonsCollection.insertOne(lessonToInsert);
    await usersCollection.updateOne(
      { uid: req.userUid },
      { $inc: { totalLessonsCreated: 1 } },
      { upsert: true }
    );

    res.status(201).send({
      insertedId: result.insertedId,
      message: "Lesson successfully created.",
    });
  } catch (error) {
    res.status(500).send({ message: "Server failed to create lesson." });
  }
});

// 8. Lesson Details 

app.get("/lessons/:id", async (req, res) => {
  try {
    const lessonId = req.params.id;
    if (!ObjectId.isValid(lessonId))
      return res.status(400).send({ message: "Invalid Lesson ID." });

    const objectId = new ObjectId(lessonId);
    const lesson = await lessonsCollection.findOne({ _id: objectId });
    if (!lesson) return res.status(404).send({ message: "Lesson not found." });

    if (!lesson.isPremium) {
      await lessonsCollection.updateOne(
        { _id: objectId },
        { $inc: { viewsCount: 1 } }
      );
      return res.send(lesson);
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(403)
        .send({ message: "Premium lesson. Upgrade required." });
    }

    try {
      const token = authHeader.split(" ")[1];
      const secret = process.env.JWT_SECRET || process.env.ACCESS_TOKEN_SECRET;
      const decoded = jwt.verify(token, secret);

      const user = await usersCollection.findOne({ uid: decoded.uid });
      if (!user || (user.isPremium !== true && user.uid !== lesson.creatorId)) {
        return res
          .status(403)
          .send({ message: "Premium subscription required to view." });
      }

      await lessonsCollection.updateOne(
        { _id: objectId },
        { $inc: { viewsCount: 1 } }
      );
      res.send(lesson);
    } catch (error) {
      console.error("JWT verification failed:", error.message);
      return res.status(403).send({ message: "Invalid token" });
    }
  } catch (error) {
    console.error("Fetch lesson failed:", error);
    res.status(500).send({ message: "Server failed to fetch lesson." });
  }
});

// Get Similar Lessons by Category

app.get("/lessons/:id/similar", async (req, res) => {
  try {
    const lessonId = req.params.id;
    const category = req.query.category;

    if (!ObjectId.isValid(lessonId)) {
      return res.status(400).send({ message: "Invalid Lesson ID." });
    }

    const objectId = new ObjectId(lessonId);
    const filter = {
      _id: { $ne: objectId },
      ...(category && { category: category }),
      isPremium: false,
    };

    const similarLessons = await lessonsCollection
      .find(filter)
      .limit(5)
      .toArray();

    res.send(similarLessons || []);
  } catch (error) {
    console.error("Fetch similar lessons failed:", error);
    res
      .status(500)
      .send({ message: "Server failed to fetch similar lessons." });
  }
});

// 9. Gets Comments

app.get("/comments/:lessonId", async (req, res) => {
  try {
    const lessonId = req.params.lessonId;
    const comments = await commentsCollection
      .find({ lessonId })
      .sort({ createdAt: -1 })
      .toArray();
    const normalized = comments.map((c) => ({
      _id: c._id,
      text: c.text || c.commentText || "",
      userId: c.userId || c.commentedBy || c.user || "",
      userName: c.userName || c.userName || "",
      userPhoto: c.userPhoto || c.photoURL || "",
      createdAt: c.createdAt,
    }));
    res.status(200).json(normalized);
  } catch (error) {
    console.error("Error fetching comments:", error);
    res
      .status(500)
      .json({ message: "Internal server error while fetching comments." });
  }
});

// Delete a comment by id

app.delete("/comments/:id", verifyJWT, async (req, res) => {
  try {
    const commentId = req.params.id;
    if (!ObjectId.isValid(commentId))
      return res.status(400).send({ message: "Invalid comment ID." });

    const comment = await commentsCollection.findOne({
      _id: new ObjectId(commentId),
    });
    if (!comment)
      return res.status(404).send({ message: "Comment not found." });

    if (comment.userId !== req.userUid && comment.commentedBy !== req.userUid) {
      const user = await usersCollection.findOne({ uid: req.userUid });
      if (!user || user.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Unauthorized to delete this comment." });
      }
    }

    await commentsCollection.deleteOne({ _id: new ObjectId(commentId) });
    return res.send({ message: "Comment deleted." });
  } catch (error) {
    console.error("Delete comment failed:", error);
    res.status(500).send({ message: "Failed to delete comment." });
  }
});

// 10. Post Comment

app.post("/comments", verifyJWT, async (req, res) => {
  try {
    const body = req.body || {};
    const lessonId = body.lessonId || body.lesson || body.lesson_id;
    const commentText =
      body.commentText || body.text || body.comment || body.commentText;
    const commentedBy =
      body.commentedBy || body.userId || body.user || req.userUid;
    const userName =
      body.userName ||
      body.userName ||
      body.userName ||
      body.userName ||
      body.userName ||
      body.userName ||
      body.userName ||
      req.userEmail ||
      "";
    const userPhoto = body.userPhoto || body.photoURL || "";

    if (!lessonId || !commentText || !commentedBy) {
      return res.status(400).send({ message: "Invalid comment data." });
    }

    const newComment = {
      lessonId,
      commentText,
      text: commentText,
      commentedBy,
      userId: commentedBy,
      userName,
      userPhoto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await commentsCollection.insertOne(newComment);
    res.status(201).send({
      insertedId: result.insertedId,
      message: "Comment posted.",
      comment: newComment,
    });
  } catch (error) {
    console.error("Failed to post comment:", error);
    res.status(500).send({ message: "Failed to post comment." });
  }
});

// 11. Toggle Favourites


app.patch("/lessons/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const updatedData = req.body;

    const query = { _id: new ObjectId(id), creatorId: req.userUid };

    const result = await lessonsCollection.updateOne(query, {
      $set: { ...updatedData, updatedAt: new Date() },
    });

    if (result.matchedCount === 0) {
      return res
        .status(404)
        .send({ message: "Lesson not found or Unauthorized" });
    }

    res.send({ success: true, message: "Lesson updated successfully" });
  } catch (error) {
    res.status(500).send({ message: "Update failed" });
  }
});

app.get("/api/lessons/favorites/:uid", verifyJWT, async (req, res) => {
  try {
    const uid = req.params.uid;
    const favorites = await favouritesCollection
      .find({ userId: uid })
      .toArray();

    if (!favorites || favorites.length === 0) return res.send([]);

    const lessonIds = favorites.map((f) => new ObjectId(f.lessonId));
    const favoriteLessons = await lessonsCollection
      .find({ _id: { $in: lessonIds } })
      .toArray();

    res.send(favoriteLessons);
  } catch (error) {
    res.status(500).send({ message: "Error fetching favorites" });
  }
});




// ২. Manage Users

app.get("/users/all", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find().toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch users" });
  }
});

// ৩. Manage Users: Promote/Demote (Universal Role Update)

app.put("/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;
  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role: role } }
    );
    res.send({ success: true, message: `User role updated to ${role}` });
  } catch (error) {
    res.status(500).send({ message: "Failed to update role" });
  }
});

app.patch("/users/admin/:id", verifyJWT, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role: "admin" } }
    );
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to promote user" });
  }
});

// ৪. Manage Users: Delete User

app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await usersCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true, message: "User deleted successfully" });
  } catch (error) {
    res.status(500).send({ message: "Failed to delete user" });
  }
});

// ৫. Admin Lessons

app.get("/admin/lessons", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const status = req.query.status;
    let query = {};
    if (status === "pending") {
      query = { isReviewed: false };
    } else if (status === "reported") {
      query = { reportedCount: { $gt: 0 } };
    }
    const lessons = await lessonsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    res.send(lessons);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch admin lessons" });
  }
});

// ৬. Admin: Approve Lesson

app.patch(
  "/admin/lessons/approve/:id",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const lessonId = req.params.id;
      await lessonsCollection.updateOne(
        { _id: new ObjectId(lessonId) },
        { $set: { isReviewed: true } }
      );
      res.send({ message: "Lesson approved and published." });
    } catch (error) {
      res.status(500).send({ message: "Failed to approve lesson." });
    }
  }
);

// ৭. Admin: Toggle Featured

app.patch(
  "/admin/lessons/featured/:id",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      const { isFeatured } = req.body;
      const result = await lessonsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { isFeatured: isFeatured, isReviewed: true } }
      );
      if (result.matchedCount === 0) {
        return res
          .status(404)
          .send({ success: false, message: "Lesson not found!" });
      }
      res.send({
        success: true,
        message: isFeatured
          ? "Lesson marked as Featured ✨"
          : "Featured status removed.",
      });
    } catch (error) {
      res
        .status(500)
        .send({ success: false, message: "Internal Server Error" });
    }
  }
);

// ৮. Admin: Resolve Report

app.patch(
  "/admin/lessons/resolve-report/:id",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const id = req.params.id;
      await lessonsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { reportedCount: 0, isReviewed: true } }
      );
      await lessonsReportsCollection.deleteMany({ lessonId: id });
      res.send({ success: true, message: "Reports resolved." });
    } catch (error) {
      res
        .status(500)
        .send({ success: false, message: "Failed to resolve reports." });
    }
  }
);

// ৯. Admin: Permanent Delete Lesson

app.delete("/admin/lessons/:id", verifyJWT, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await lessonsCollection.deleteOne({ _id: new ObjectId(id) });
    await lessonsReportsCollection.deleteMany({ lessonId: id });
    res.send({ success: true, message: "Lesson permanently deleted." });
  } catch (error) {
    res.status(500).send({ message: "Failed to delete lesson." });
  }
});

// ১. Like/Unlike Toggle API

app.post("/lessons/:id/like", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const userEmail = req.userEmail;

    if (!ObjectId.isValid(lessonId)) {
      return res.status(400).send({ message: "Invalid Lesson ID" });
    }

    const query = { _id: new ObjectId(lessonId) };
    const lesson = await lessonsCollection.findOne(query);

    if (!lesson) {
      return res.status(404).send({ message: "Lesson not found" });
    }

  
    const likedBy = lesson.likedBy || [];
    const hasLiked = likedBy.includes(userEmail);

    let updateDoc;
    if (hasLiked) {
      updateDoc = {
        $pull: { likedBy: userEmail },
        $inc: { likesCount: -1 },
      };
    } else {
      updateDoc = {
        $addToSet: { likedBy: userEmail },
        $inc: { likesCount: 1 },
      };
    }

    await lessonsCollection.updateOne(query, updateDoc);

    const updatedLesson = await lessonsCollection.findOne(query);

    res.send({
      success: true,
      isLiked: !hasLiked,
      currentLikes: updatedLesson.likesCount || 0,
    });
  } catch (error) {
    console.error("Like Error:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

// ২. Report Lesson API

app.post("/lessons/:id/report", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const { reportReason, reporterEmail } = req.body;

    await lessonsCollection.updateOne(
      { _id: new ObjectId(lessonId) },
      { $inc: { reportedCount: 1 } }
    );

    const reportDoc = {
      lessonId: lessonId,
      reporterEmail,
      reportReason,
      createdAt: new Date(),
    };

    await lessonsReportsCollection.insertOne(reportDoc);

    res.send({ success: true, message: "Report submitted successfully." });
  } catch (error) {
    res.status(500).send({ message: "Reporting failed." });
  }
});

// --- Admin Stats Section (Dashboard) ---

app.get("/admin/total-users", verifyJWT, verifyAdmin, async (req, res) => {
  const total = await usersCollection.estimatedDocumentCount();
  res.send({ total });
});

app.get("/admin/total-lessons", verifyJWT, verifyAdmin, async (req, res) => {
  const total = await lessonsCollection.countDocuments();
  res.send({ total });
});

app.get(
  "/admin/reported-lessons-count",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    const total = await lessonsCollection.countDocuments({
      reportedCount: { $gt: 0 },
    });
    res.send({ total });
  }
);

app.get(
  "/admin/most-active-contributors",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    const result = await lessonsCollection
      .aggregate([
        { $group: { _id: "$creatorEmail", lessonsCreated: { $sum: 1 } } },
        { $sort: { lessonsCreated: -1 } },
        { $limit: 5 },
        { $project: { name: "$_id", lessonsCreated: 1, _id: 0 } },
      ])
      .toArray();
    res.send(result);
  }
);

app.get("/admin/todays-lessons", verifyJWT, verifyAdmin, async (req, res) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const total = await lessonsCollection.countDocuments({
    createdAt: { $gte: today },
  });
  res.send({ total });
});

// --- User Section ---

app.get("/lessons/my-lessons/:uid", verifyJWT, async (req, res) => {
  try {
    const uid = req.params.uid;
    const userLessons = await lessonsCollection
      .find({
        creatorId: uid,
        isDeletedByUser: { $ne: true },
      })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(userLessons);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch user lessons." });
  }
});

// --- Listener & Root ---

// একদম শেষে গিয়ে আগের module.expors লাইনটি মুছে এটি দিন
app.get("/", (req, res) =>
  res.send("✅ Digital Life Lessons Full API Running")
);

// Vercel এর জন্য এক্সপোর্ট
module.exports = app; 

// লোকাল হোস্টে চালানোর জন্য
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
}