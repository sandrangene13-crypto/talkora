require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error(
    "ERROR: JWT_SECRET must exist in .env and be at least 32 characters long."
  );
  process.exit(1);
}

/* =========================================================
   FOLDERS
========================================================= */

const dataFolder = path.join(__dirname, "data");
const publicFolder = path.join(__dirname, "public");
const uploadsFolder = path.join(publicFolder, "uploads");

fs.mkdirSync(dataFolder, { recursive: true });
fs.mkdirSync(uploadsFolder, { recursive: true });

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(path.join(dataFolder, "talkora.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT,
    message_type TEXT NOT NULL DEFAULT 'text',
    media_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_messages_pair
  ON messages(sender_id, receiver_id, id);

  CREATE INDEX IF NOT EXISTS idx_messages_receiver
  ON messages(receiver_id, id);
`);

/*
  Existing databases may already have the old messages table.
  Add the new columns if they are missing.
*/

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();

  const exists = columns.some((item) => item.name === column);

  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

ensureColumn("messages", "message_type", "TEXT NOT NULL DEFAULT 'text'");
ensureColumn("messages", "media_url", "TEXT");

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

/*
  The frontend sends image/audio data as base64 JSON.
  10 KB was too small for media uploads.
*/
app.use(express.json({ limit: "8mb" }));

app.use(
  express.urlencoded({
    extended: true,
    limit: "8mb"
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests. Please try again later."
  }
});

app.use("/api/", apiLimiter);

app.use(express.static(publicFolder));

/* =========================================================
   HELPERS
========================================================= */

function validUsername(username) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(username);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 128;
}

function cleanUsername(username) {
  return String(username || "").trim();
}

function cleanEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function getUserById(id) {
  return db
    .prepare(
      `
      SELECT id, username, email, created_at
      FROM users
      WHERE id = ?
      `
    )
    .get(id);
}

function userExists(id) {
  return Boolean(
    db
      .prepare("SELECT id FROM users WHERE id = ?")
      .get(id)
  );
}

function isValidMessageType(type) {
  return ["text", "image", "voice"].includes(type);
}

function safeFileExtension(type) {
  if (type === "image") return ".jpg";
  if (type === "voice") return ".webm";
  return "";
}

/* =========================================================
   AUTHENTICATION MIDDLEWARE
========================================================= */

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = header.substring(7).trim();

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = getUserById(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "User account no longer exists."
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

/* =========================================================
   AUTH ROUTES
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const email = cleanEmail(req.body.email);
    const password = req.body.password;

    if (!validUsername(username)) {
      return res.status(400).json({
        error:
          "Username must be 3–30 characters and contain only letters, numbers, or underscores."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: "Password must be between 8 and 128 characters."
      });
    }

    const existing = db
      .prepare(
        `
        SELECT id
        FROM users
        WHERE username = ? COLLATE NOCASE
           OR email = ? COLLATE NOCASE
        `
      )
      .get(username, email);

    if (existing) {
      return res.status(409).json({
        error: "Username or email is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        `
        INSERT INTO users
        (username, email, password_hash)
        VALUES (?, ?, ?)
        `
      )
      .run(username, email, passwordHash);

    const user = getUserById(result.lastInsertRowid);
    const token = createToken(user);

    return res.status(201).json({
      token,
      user
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      error: "Registration failed."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim();
    const password = req.body.password;

    if (!identifier || !password) {
      return res.status(400).json({
        error: "Username/email and password are required."
      });
    }

    const user = db
      .prepare(
        `
        SELECT *
        FROM users
        WHERE username = ? COLLATE NOCASE
           OR email = ? COLLATE NOCASE
        `
      )
      .get(identifier, identifier);

    if (!user) {
      return res.status(401).json({
        error: "Invalid login details."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Invalid login details."
      });
    }

    const safeUser = getUserById(user.id);
    const token = createToken(safeUser);

    return res.json({
      token,
      user: safeUser
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================================================
   USER ROUTES
========================================================= */

app.get("/api/me", authenticate, (req, res) => {
  res.json({
    user: req.user
  });
});

app.get("/api/users/search", authenticate, (req, res) => {
  const query = String(req.query.q || "").trim();

  if (!query) {
    return res.json({
      users: []
    });
  }

  const users = db
    .prepare(
      `
      SELECT id, username, email, created_at
      FROM users
      WHERE id != ?
        AND username LIKE ? COLLATE NOCASE
      ORDER BY username ASC
      LIMIT 30
      `
    )
    .all(req.user.id, `%${query}%`);

  res.json({
    users
  });
});

/* =========================================================
   PRIVATE MESSAGE HISTORY
========================================================= */

app.get("/api/messages/:userId", authenticate, (req, res) => {
  const otherUserId = Number(req.params.userId);

  if (!Number.isInteger(otherUserId) || otherUserId <= 0) {
    return res.status(400).json({
      error: "Invalid user ID."
    });
  }

  if (otherUserId === req.user.id) {
    return res.status(400).json({
      error: "You cannot open a conversation with yourself."
    });
  }

  if (!userExists(otherUserId)) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  /*
    IMPORTANT:
    Only messages between the logged-in user and the selected user
    are returned.

    This prevents User A from receiving User B ↔ User C messages.
  */

  const messages = db
    .prepare(
      `
      SELECT
        m.id,
        m.sender_id,
        m.receiver_id,
        m.content,
        m.message_type,
        m.media_url,
        m.created_at
      FROM messages m
      WHERE
        (
          m.sender_id = ?
          AND m.receiver_id = ?
        )
        OR
        (
          m.sender_id = ?
          AND m.receiver_id = ?
        )
      ORDER BY m.id ASC
      LIMIT 200
      `
    )
    .all(
      req.user.id,
      otherUserId,
      otherUserId,
      req.user.id
    );

  res.json({
    messages
  });
});

/* =========================================================
   MEDIA UPLOAD
========================================================= */

app.post("/api/media", authenticate, (req, res) => {
  try {
    const { data, type } = req.body;

    if (!data || !type) {
      return res.status(400).json({
        error: "Media data and type are required."
      });
    }

    if (!["image", "voice"].includes(type)) {
      return res.status(400).json({
        error: "Unsupported media type."
      });
    }

    if (typeof data !== "string") {
      return res.status(400).json({
        error: "Invalid media data."
      });
    }

    let mimeType;
    let base64Data;

    if (type === "image") {
      const match = data.match(
        /^data:(image\/(?:jpeg|jpg|png|webp|gif));base64,(.+)$/i
      );

      if (!match) {
        return res.status(400).json({
          error: "Invalid image format."
        });
      }

      mimeType = match[1].toLowerCase();
      base64Data = match[2];
    } else {
      const match = data.match(
        /^data:(audio\/(?:webm|ogg|mpeg|mp4));base64,(.+)$/i
      );

      if (!match) {
        return res.status(400).json({
          error: "Invalid audio format."
        });
      }

      mimeType = match[1].toLowerCase();
      base64Data = match[2];
    }

    const buffer = Buffer.from(base64Data, "base64");

    /*
      Keep individual uploads reasonably small.
    */
    const maxSize = type === "image"
      ? 5 * 1024 * 1024
      : 5 * 1024 * 1024;

    if (buffer.length > maxSize) {
      return res.status(413).json({
        error: "File is too large. Maximum size is 5MB."
      });
    }

    let extension;

    if (type === "image") {
      if (mimeType.includes("png")) extension = ".png";
      else if (mimeType.includes("webp")) extension = ".webp";
      else if (mimeType.includes("gif")) extension = ".gif";
      else extension = ".jpg";
    } else {
      extension = safeFileExtension(type);
    }

    const filename =
      `${Date.now()}-${req.user.id}-${Math.random()
        .toString(36)
        .substring(2, 10)}${extension}`;

    const filePath = path.join(uploadsFolder, filename);

    fs.writeFileSync(filePath, buffer);

    const mediaUrl = `/uploads/${filename}`;

    return res.status(201).json({
      url: mediaUrl,
      type
    });
  } catch (error) {
    console.error("Media upload error:", error);

    return res.status(500).json({
      error: "Media upload failed."
    });
  }
});

/* =========================================================
   SOCKET.IO
========================================================= */

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: false
  },
  maxHttpBufferSize: 8 * 1024 * 1024
});

/*
  Map user ID -> Set of socket IDs.
  A user can be connected on more than one device/tab.
*/

const onlineUsers = new Map();

function addOnlineUser(userId, socketId) {
  const key = Number(userId);

  if (!onlineUsers.has(key)) {
    onlineUsers.set(key, new Set());
  }

  onlineUsers.get(key).add(socketId);
}

function removeOnlineUser(userId, socketId) {
  const key = Number(userId);

  const sockets = onlineUsers.get(key);

  if (!sockets) return;

  sockets.delete(socketId);

  if (sockets.size === 0) {
    onlineUsers.delete(key);
  }
}

function emitToUser(userId, event, payload) {
  io.to(`user:${Number(userId)}`).emit(event, payload);
}

/* =========================================================
   SOCKET AUTH
========================================================= */

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Authentication required."));
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = getUserById(decoded.id);

    if (!user) {
      return next(new Error("User not found."));
    }

    socket.user = user;

    next();
  } catch (error) {
    next(new Error("Invalid or expired session."));
  }
});

/* =========================================================
   SOCKET CONNECTION
========================================================= */

io.on("connection", (socket) => {
  const userId = socket.user.id;

  console.log(`TAVLIK user connected: ${socket.user.username}`);

  addOnlineUser(userId, socket.id);

  socket.join(`user:${userId}`);

  /*
    Send current online status to the newly connected user.
  */

  socket.emit("online_users", {
    users: Array.from(onlineUsers.keys())
  });

  /*
    Tell everybody that this user is online.
  */

  socket.broadcast.emit("user_online", {
    userId
  });

  /* =======================================================
     PRIVATE TEXT MESSAGE
  ======================================================= */

  socket.on("send_message", (payload) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const content = String(payload?.content || "").trim();

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        return;
      }

      if (receiverId === userId) {
        return;
      }

      if (!content || content.length > 2000) {
        return;
      }

      /*
        Critical authorization:
        the receiver must actually exist.
      */

      const receiver = getUserById(receiverId);

      if (!receiver) {
        return;
      }

      const result = db
        .prepare(
          `
          INSERT INTO messages
          (
            sender_id,
            receiver_id,
            content,
            message_type,
            media_url
          )
          VALUES (?, ?, ?, 'text', NULL)
          `
        )
        .run(
          userId,
          receiverId,
          content
        );

      const message = db
        .prepare(
          `
          SELECT
            id,
            sender_id,
            receiver_id,
            content,
            message_type,
            media_url,
            created_at
          FROM messages
          WHERE id = ?
          `
        )
        .get(result.lastInsertRowid);

      /*
        Only sender and receiver receive the message.
      */

      emitToUser(userId, "new_message", message);
      emitToUser(receiverId, "new_message", message);
    } catch (error) {
      console.error("send_message error:", error);
    }
  });

  /* =======================================================
     PRIVATE MEDIA MESSAGE
  ======================================================= */

  socket.on("send_media_message", (payload) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const mediaUrl = String(payload?.mediaUrl || "").trim();
      const type = String(payload?.type || "").trim();

      if (!Number.isInteger(receiverId) || receiverId <= 0) {
        return;
      }

      if (receiverId === userId) {
        return;
      }

      if (!userExists(receiverId)) {
        return;
      }

      if (!mediaUrl || !mediaUrl.startsWith("/uploads/")) {
        return;
      }

      if (!isValidMessageType(type) || type === "text") {
        return;
      }

      const result = db
        .prepare(
          `
          INSERT INTO messages
          (
            sender_id,
            receiver_id,
            content,
            message_type,
            media_url
          )
          VALUES (?, ?, NULL, ?, ?)
          `
        )
        .run(
          userId,
          receiverId,
          type,
          mediaUrl
        );

      const message = db
        .prepare(
          `
          SELECT
            id,
            sender_id,
            receiver_id,
            content,
            message_type,
            media_url,
            created_at
          FROM messages
          WHERE id = ?
          `
        )
        .get(result.lastInsertRowid);

      emitToUser(userId, "new_message", message);
      emitToUser(receiverId, "new_message", message);
    } catch (error) {
      console.error("send_media_message error:", error);
    }
  });

  /* =======================================================
     TYPING
  ======================================================= */

  socket.on("typing", (payload) => {
    const receiverId = Number(payload?.receiverId);

    if (!Number.isInteger(receiverId)) {
      return;
    }

    if (receiverId === userId) {
      return;
    }

    if (!userExists(receiverId)) {
      return;
    }

    emitToUser(receiverId, "user_typing", {
      userId
    });
  });

  socket.on("stop_typing", (payload) => {
    const receiverId = Number(payload?.receiverId);

    if (!Number.isInteger(receiverId)) {
      return;
    }

    if (receiverId === userId) {
      return;
    }

    if (!userExists(receiverId)) {
      return;
    }

    emitToUser(receiverId, "user_stopped_typing", {
      userId
    });
  });

  /* =======================================================
     VIDEO CALL: CALL USER
  ======================================================= */

  socket.on("call_user", (payload) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const offer = payload?.offer;

      if (!Number.isInteger(receiverId)) {
        return;
      }

      if (receiverId === userId) {
        return;
      }

      if (!userExists(receiverId)) {
        return;
      }

      if (!offer) {
        return;
      }

      emitToUser(receiverId, "incoming_call", {
        callerId: userId,
        callerUsername: socket.user.username,
        offer
      });
    } catch (error) {
      console.error("call_user error:", error);
    }
  });

  /* =======================================================
     VIDEO CALL: ACCEPT
  ======================================================= */

  socket.on("call_accepted", (payload) => {
    try {
      const callerId = Number(payload?.callerId);
      const answer = payload?.answer;

      if (!Number.isInteger(callerId)) {
        return;
      }

      if (callerId === userId) {
        return;
      }

      if (!userExists(callerId)) {
        return;
      }

      if (!answer) {
        return;
      }

      emitToUser(callerId, "call_accepted", {
        accepterId: userId,
        answer
      });
    } catch (error) {
      console.error("call_accepted error:", error);
    }
  });

  /* =======================================================
     VIDEO CALL: ICE CANDIDATE
  ======================================================= */

  socket.on("ice_candidate", (payload) => {
    try {
      const receiverId = Number(payload?.receiverId);
      const candidate = payload?.candidate;

      if (!Number.isInteger(receiverId)) {
        return;
      }

      if (receiverId === userId) {
        return;
      }

      if (!userExists(receiverId)) {
        return;
      }

      if (!candidate) {
        return;
      }

      emitToUser(receiverId, "ice_candidate", {
        senderId: userId,
        candidate
      });
    } catch (error) {
      console.error("ice_candidate error:", error);
    }
  });

  /* =======================================================
     VIDEO CALL: REJECT
  ======================================================= */

  socket.on("call_rejected", (payload) => {
    try {
      const callerId = Number(payload?.callerId);

      if (!Number.isInteger(callerId)) {
        return;
      }

      if (callerId === userId) {
        return;
      }

      if (!userExists(callerId)) {
        return;
      }

      emitToUser(callerId, "call_rejected", {
        userId
      });
    } catch (error) {
      console.error("call_rejected error:", error);
    }
  });

  /* =======================================================
     VIDEO CALL: END
  ======================================================= */

  socket.on("end_call", (payload) => {
    try {
      const receiverId = Number(payload?.receiverId);

      if (!Number.isInteger(receiverId)) {
        return;
      }

      if (receiverId === userId) {
        return;
      }

      if (!userExists(receiverId)) {
        return;
      }

      emitToUser(receiverId, "end_call", {
        userId
      });
    } catch (error) {
      console.error("end_call error:", error);
    }
  });

  /* =======================================================
     DISCONNECT
  ======================================================= */

  socket.on("disconnect", () => {
    removeOnlineUser(userId, socket.id);

    console.log(`TAVLIK user disconnected: ${socket.user.username}`);

    if (!onlineUsers.has(userId)) {
      socket.broadcast.emit("user_offline", {
        userId
      });
    }
  });
});

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get("*splat", (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return next();
  }

  if (req.path.startsWith("/socket.io/")) {
    return next();
  }

  res.sendFile(path.join(publicFolder, "index.html"));
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error("Server error:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Internal server error."
  });
});

/* =========================================================
   START SERVER
========================================================= */

server.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("====================================");
  console.log("          TAVLIK IS RUNNING");
  console.log("====================================");
  console.log(`Local:   http://localhost:${PORT}`);
  console.log(`Port:    ${PORT}`);
  console.log("Private messaging: ENABLED");
  console.log("Media messages:    ENABLED");
  console.log("Video signaling:   ENABLED");
  console.log("====================================");
  console.log("");
});
