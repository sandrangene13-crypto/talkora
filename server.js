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
    throw new Error("JWT_SECRET must be at least 32 characters long.");
}

/* =========================================================
   DIRECTORIES
========================================================= */

const publicFolder = path.join(__dirname, "public");
const dataFolder = path.join(__dirname, "data");
const uploadFolder = path.join(publicFolder, "uploads");

fs.mkdirSync(publicFolder, { recursive: true });
fs.mkdirSync(dataFolder, { recursive: true });
fs.mkdirSync(uploadFolder, { recursive: true });

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(
    path.join(dataFolder, "talkora.db")
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/* =========================================================
   DATABASE TABLES
========================================================= */

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
        content TEXT NOT NULL DEFAULT '',
        message_type TEXT NOT NULL DEFAULT 'text',
        media_url TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (sender_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY (receiver_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );
`);

/* =========================================================
   DATABASE MIGRATION
========================================================= */

function addColumnIfMissing(tableName, columnName, definition) {
    const columns = db
        .prepare(`PRAGMA table_info(${tableName})`)
        .all();

    const exists = columns.some(
        column => column.name === columnName
    );

    if (!exists) {
        db.exec(`
            ALTER TABLE ${tableName}
            ADD COLUMN ${columnName} ${definition}
        `);
    }
}

addColumnIfMissing(
    "messages",
    "message_type",
    "TEXT NOT NULL DEFAULT 'text'"
);

addColumnIfMissing(
    "messages",
    "media_url",
    "TEXT"
);

/* =========================================================
   INDEXES
========================================================= */

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver
    ON messages(sender_id, receiver_id, id);

    CREATE INDEX IF NOT EXISTS idx_messages_receiver_sender
    ON messages(receiver_id, sender_id, id);

    CREATE INDEX IF NOT EXISTS idx_users_username
    ON users(username);

    CREATE INDEX IF NOT EXISTS idx_users_email
    ON users(email);
`);

/* =========================================================
   EXPRESS SECURITY
========================================================= */

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(
    express.json({
        limit: "12mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "12mb"
    })
);

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many requests. Please try again later."
    }
});

app.use("/api", apiLimiter);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
    express.static(publicFolder)
);

/* =========================================================
   SOCKET.IO
========================================================= */

const io = new Server(server, {
    cors: {
        origin: true,
        credentials: true
    }
});

/* =========================================================
   VALIDATION
========================================================= */

function validUsername(username) {
    return (
        typeof username === "string" &&
        /^[a-zA-Z0-9_]{3,30}$/.test(username)
    );
}

function validEmail(email) {
    return (
        typeof email === "string" &&
        email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        password.length <= 128
    );
}

/* =========================================================
   USER HELPERS
========================================================= */

function getUserById(id) {
    return db
        .prepare(`
            SELECT
                id,
                username,
                email,
                created_at
            FROM users
            WHERE id = ?
        `)
        .get(id);
}

function userExists(id) {
    return Boolean(
        db
            .prepare(`
                SELECT id
                FROM users
                WHERE id = ?
            `)
            .get(id)
    );
}

/* =========================================================
   JWT
========================================================= */

function createToken(user) {
    return jwt.sign(
        {
            id: Number(user.id),
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function authenticate(req, res, next) {
    const authorization =
        req.headers.authorization;

    if (
        !authorization ||
        !authorization.startsWith("Bearer ")
    ) {
        return res.status(401).json({
            error: "Authentication required."
        });
    }

    const token =
        authorization.slice(7);

    try {
        const decoded =
            jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch {
        return res.status(401).json({
            error: "Invalid or expired token."
        });
    }
}

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/auth/register",
    async (req, res) => {
        try {
            let {
                username,
                email,
                password
            } = req.body || {};

            username =
                typeof username === "string"
                    ? username.trim()
                    : "";

            email =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            if (
                !validUsername(username) ||
                !validEmail(email) ||
                !validPassword(password)
            ) {
                return res.status(400).json({
                    error:
                        "Username, email or password is invalid."
                });
            }

            const existing =
                db
                    .prepare(`
                        SELECT id
                        FROM users
                        WHERE
                            username = ?
                            COLLATE NOCASE
                            OR
                            email = ?
                            COLLATE NOCASE
                    `)
                    .get(
                        username,
                        email
                    );

            if (existing) {
                return res.status(409).json({
                    error:
                        "Username or email already exists."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const result =
                db
                    .prepare(`
                        INSERT INTO users
                        (
                            username,
                            email,
                            password_hash
                        )
                        VALUES (?, ?, ?)
                    `)
                    .run(
                        username,
                        email,
                        passwordHash
                    );

            const user = {
                id: Number(result.lastInsertRowid),
                username
            };

            const token =
                createToken(user);

            return res.status(201).json({
                user,
                token
            });

        } catch (error) {
            console.error(
                "Registration error:",
                error
            );

            if (
                error.code ===
                "SQLITE_CONSTRAINT_UNIQUE"
            ) {
                return res.status(409).json({
                    error:
                        "Username or email already exists."
                });
            }

            return res.status(500).json({
                error:
                    "Registration failed."
            });
        }
    }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/auth/login",
    async (req, res) => {
        try {
            let {
                email,
                password
            } = req.body || {};

            email =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            if (
                !validEmail(email) ||
                typeof password !== "string"
            ) {
                return res.status(400).json({
                    error:
                        "Invalid email or password."
                });
            }

            const user =
                db
                    .prepare(`
                        SELECT
                            id,
                            username,
                            email,
                            password_hash,
                            created_at
                        FROM users
                        WHERE email = ?
                        COLLATE NOCASE
                    `)
                    .get(email);

            if (!user) {
                return res.status(401).json({
                    error:
                        "Invalid email or password."
                });
            }

            const passwordCorrect =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!passwordCorrect) {
                return res.status(401).json({
                    error:
                        "Invalid email or password."
                });
            }

            const publicUser = {
                id: user.id,
                username: user.username
            };

            const token =
                createToken(publicUser);

            return res.json({
                user: publicUser,
                token
            });

        } catch (error) {
            console.error(
                "Login error:",
                error
            );

            return res.status(500).json({
                error:
                    "Login failed."
            });
        }
    }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    authenticate,
    (req, res) => {
        const user =
            getUserById(
                Number(req.user.id)
            );

        if (!user) {
            return res.status(404).json({
                error:
                    "User not found."
            });
        }

        return res.json({
            user
        });
    }
);

/* =========================================================
   USER SEARCH
========================================================= */

app.get(
    "/api/users/search",
    authenticate,
    (req, res) => {
        const query =
            typeof req.query.q === "string"
                ? req.query.q.trim()
                : "";

        if (!query) {
            return res.json({
                users: []
            });
        }

        const users =
            db
                .prepare(`
                    SELECT
                        id,
                        username,
                        created_at
                    FROM users
                    WHERE
                        id != ?
                        AND username LIKE ?
                        COLLATE NOCASE
                    ORDER BY username ASC
                    LIMIT 30
                `)
                .all(
                    Number(req.user.id),
                    `%${query}%`
                );

        return res.json({
            users
        });
    }
);

/* =========================================================
   PRIVATE MESSAGE HISTORY
========================================================= */

app.get(
    "/api/messages/:userId",
    authenticate,
    (req, res) => {
        const currentUserId =
            Number(req.user.id);

        const otherUserId =
            Number(req.params.userId);

        if (
            !Number.isInteger(otherUserId) ||
            otherUserId <= 0 ||
            otherUserId === currentUserId
        ) {
            return res.status(400).json({
                error:
                    "Invalid conversation."
            });
        }

        if (!userExists(otherUserId)) {
            return res.status(404).json({
                error:
                    "User not found."
            });
        }

        const messages =
            db
                .prepare(`
                    SELECT
                        id,
                        sender_id,
                        receiver_id,
                        content,
                        message_type,
                        media_url,
                        created_at
                    FROM messages
                    WHERE
                        (
                            sender_id = ?
                            AND receiver_id = ?
                        )
                        OR
                        (
                            sender_id = ?
                            AND receiver_id = ?
                        )
                    ORDER BY id ASC
                    LIMIT 200
                `)
                .all(
                    currentUserId,
                    otherUserId,
                    otherUserId,
                    currentUserId
                );

        return res.json({
            messages
        });
    }
);

/* =========================================================
   MEDIA UPLOAD
========================================================= */

const ALLOWED_MEDIA_TYPES = {
    image: [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif"
    ],

    audio: [
        "audio/webm",
        "audio/ogg",
        "audio/mp4",
        "audio/mpeg",
        "audio/wav"
    ]
};

const MAX_IMAGE_SIZE =
    8 * 1024 * 1024;

const MAX_AUDIO_SIZE =
    8 * 1024 * 1024;

function extensionForMime(mime) {
    const extensions = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/gif": ".gif",

        "audio/webm": ".webm",
        "audio/ogg": ".ogg",
        "audio/mp4": ".m4a",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav"
    };

    return extensions[mime] || "";
}

app.post(
    "/api/media",
    authenticate,
    (req, res) => {
        try {
            const {
                type,
                mimeType,
                data
            } = req.body || {};

            if (
                type !== "image" &&
                type !== "audio"
            ) {
                return res.status(400).json({
                    error:
                        "Unsupported media type."
                });
            }

            if (
                typeof mimeType !== "string" ||
                typeof data !== "string"
            ) {
                return res.status(400).json({
                    error:
                        "Media data is required."
                });
            }

            if (
                !ALLOWED_MEDIA_TYPES[type].includes(
                    mimeType
                )
            ) {
                return res.status(400).json({
                    error:
                        "Unsupported media format."
                });
            }

            const cleanData =
                data.includes(",")
                    ? data.slice(
                        data.indexOf(",") + 1
                    )
                    : data;

            let buffer;

            try {
                buffer =
                    Buffer.from(
                        cleanData,
                        "base64"
                    );
            } catch {
                return res.status(400).json({
                    error:
                        "Invalid media data."
                });
            }

            const maxSize =
                type === "image"
                    ? MAX_IMAGE_SIZE
                    : MAX_AUDIO_SIZE;

            if (buffer.length > maxSize) {
                return res.status(413).json({
                    error:
                        "Media file is too large."
                });
            }

            const extension =
                extensionForMime(mimeType);

            if (!extension) {
                return res.status(400).json({
                    error:
                        "Unsupported media format."
                });
            }

            const filename =
                `${Date.now()}-${Math.random()
                    .toString(36)
                    .slice(2, 12)}${extension}`;

            const filepath =
                path.join(
                    uploadFolder,
                    filename
                );

            fs.writeFileSync(
                filepath,
                buffer
            );

            return res.status(201).json({
                url:
                    `/uploads/${filename}`,
                type,
                mimeType
            });

        } catch (error) {
            console.error(
                "Media upload error:",
                error
            );

            return res.status(500).json({
                error:
                    "Media upload failed."
            });
        }
    }
);

/* =========================================================
   SOCKET.IO AUTHENTICATION
========================================================= */

io.use(
    (socket, next) => {
        const token =
            socket.handshake.auth?.token;

        if (!token) {
            return next(
                new Error(
                    "Authentication required."
                )
            );
        }

        try {
            const decoded =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            const user =
                getUserById(
                    Number(decoded.id)
                );

            if (!user) {
                return next(
                    new Error(
                        "User not found."
                    )
                );
            }

            socket.user = {
                id: user.id,
                username: user.username
            };

            next();

        } catch {
            next(
                new Error(
                    "Invalid or expired token."
                )
            );
        }
    }
);

/* =========================================================
   ONLINE USERS
========================================================= */

const onlineUsers = new Map();

function broadcastOnlineUsers() {
    io.emit(
        "online_users",
        Array.from(
            onlineUsers.keys()
        )
    );
}

/* =========================================================
   SOCKET CONNECTION
========================================================= */

io.on(
    "connection",
    socket => {
        const userId =
            Number(socket.user.id);

        console.log(
            `User connected: ${socket.user.username}`
        );

        socket.join(
            `user:${userId}`
        );

        onlineUsers.set(
            userId,
            (onlineUsers.get(userId) || 0) + 1
        );

        broadcastOnlineUsers();

        /* =================================================
           PRIVATE TEXT MESSAGE
        ================================================= */

        socket.on(
            "send_message",
            (data, callback) => {
                try {
                    const receiverId =
                        Number(
                            data?.receiverId
                        );

                    const content =
                        typeof data?.content === "string"
                            ? data.content.trim()
                            : "";

                    if (
                        !Number.isInteger(receiverId) ||
                        receiverId <= 0
                    ) {
                        return callback?.({
                            error:
                                "Invalid receiver."
                        });
                    }

                    if (receiverId === userId) {
                        return callback?.({
                            error:
                                "You cannot message yourself."
                        });
                    }

                    if (!userExists(receiverId)) {
                        return callback?.({
                            error:
                                "Receiver not found."
                        });
                    }

                    if (
                        !content ||
                        content.length > 2000
                    ) {
                        return callback?.({
                            error:
                                "Message must contain between 1 and 2000 characters."
                        });
                    }

                    const result =
                        db
                            .prepare(`
                                INSERT INTO messages
                                (
                                    sender_id,
                                    receiver_id,
                                    content,
                                    message_type
                                )
                                VALUES (?, ?, ?, 'text')
                            `)
                            .run(
                                userId,
                                receiverId,
                                content
                            );

                    const message =
                        db
                            .prepare(`
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
                            `)
                            .get(
                                result.lastInsertRowid
                            );

                    /*
                     * Only the sender and receiver
                     * receive this message.
                     */
                    io.to(`user:${userId}`)
                        .to(`user:${receiverId}`)
                        .emit(
                            "new_message",
                            message
                        );

                    callback?.({
                        success: true,
                        message
                    });

                } catch (error) {
                    console.error(
                        "Send message error:",
                        error
                    );

                    callback?.({
                        error:
                            "Message could not be sent."
                    });
                }
            }
        );

        /* =================================================
           PRIVATE MEDIA MESSAGE
        ================================================= */

        socket.on(
            "send_media_message",
            (data, callback) => {
                try {
                    const receiverId =
                        Number(
                            data?.receiverId
                        );

                    const type =
                        data?.type;

                    const mediaUrl =
                        typeof data?.mediaUrl === "string"
                            ? data.mediaUrl.trim()
                            : "";

                    if (
                        !Number.isInteger(receiverId) ||
                        receiverId <= 0 ||
                        receiverId === userId
                    ) {
                        return callback?.({
                            error:
                                "Invalid receiver."
                        });
                    }

                    if (!userExists(receiverId)) {
                        return callback?.({
                            error:
                                "Receiver not found."
                        });
                    }

                    if (
                        type !== "image" &&
                        type !== "audio"
                    ) {
                        return callback?.({
                            error:
                                "Invalid media type."
                        });
                    }

                    if (
                        !mediaUrl.startsWith(
                            "/uploads/"
                        )
                    ) {
                        return callback?.({
                            error:
                                "Invalid media URL."
                        });
                    }

                    const content =
                        type === "image"
                            ? "[Image]"
                            : "[Voice message]";

                    const result =
                        db
                            .prepare(`
                                INSERT INTO messages
                                (
                                    sender_id,
                                    receiver_id,
                                    content,
                                    message_type,
                                    media_url
                                )
                                VALUES (?, ?, ?, ?, ?)
                            `)
                            .run(
                                userId,
                                receiverId,
                                content,
                                type,
                                mediaUrl
                            );

                    const message =
                        db
                            .prepare(`
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
                            `)
                            .get(
                                result.lastInsertRowid
                            );

                    io.to(`user:${userId}`)
                        .to(`user:${receiverId}`)
                        .emit(
                            "new_message",
                            message
                        );

                    callback?.({
                        success: true,
                        message
                    });

                } catch (error) {
                    console.error(
                        "Send media message error:",
                        error
                    );

                    callback?.({
                        error:
                            "Media message could not be sent."
                    });
                }
            }
        );

        /* =================================================
           TYPING
        ================================================= */

        socket.on(
            "typing",
            data => {
                const receiverId =
                    Number(
                        data?.receiverId
                    );

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0 ||
                    receiverId === userId ||
                    !userExists(receiverId)
                ) {
                    return;
                }

                io.to(
                    `user:${receiverId}`
                ).emit(
                    "user_typing",
                    {
                        userId
                    }
                );
            }
        );

        socket.on(
            "stop_typing",
            data => {
                const receiverId =
                    Number(
                        data?.receiverId
                    );

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0 ||
                    receiverId === userId ||
                    !userExists(receiverId)
                ) {
                    return;
                }

                io.to(
                    `user:${receiverId}`
                ).emit(
                    "user_stopped_typing",
                    {
                        userId
                    }
                );
            }
        );

        /* =================================================
           VOICE / VIDEO CALL SIGNALING
        ================================================= */

        function forwardCallOffer(data) {
            const receiverId =
                Number(
                    data?.receiverId
                );

            if (
                !Number.isInteger(receiverId) ||
                receiverId <= 0 ||
                receiverId === userId ||
                !userExists(receiverId)
            ) {
                return;
            }

            const callType =
                data?.callType === "video"
                    ? "video"
                    : "voice";

            io.to(
                `user:${receiverId}`
            ).emit(
                "incoming_call",
                {
                    callerId: userId,
                    callerUsername:
                        socket.user.username,
                    callType,
                    offer:
                        data?.offer || null
                }
            );
        }

        /*
         * Supports the original event name.
         */
        socket.on(
            "call_user",
            data => {
                forwardCallOffer(data);
            }
        );

        /*
         * Supports the frontend call event.
         */
        socket.on(
            "call_offer",
            data => {
                forwardCallOffer(data);
            }
        );

        /* =================================================
           CALL ACCEPTED
        ================================================= */

        socket.on(
            "call_accepted",
            data => {
                const callerId =
                    Number(
                        data?.callerId
                    );

                if (
                    !Number.isInteger(callerId) ||
                    callerId <= 0 ||
                    callerId === userId ||
                    !userExists(callerId)
                ) {
                    return;
                }

                io.to(
                    `user:${callerId}`
                ).emit(
                    "call_accepted",
                    {
                        accepterId: userId,
                        answer:
                            data?.answer || null
                    }
                );
            }
        );

        /* =================================================
           CALL REJECTED
        ================================================= */

        socket.on(
            "call_rejected",
            data => {
                const callerId =
                    Number(
                        data?.callerId
                    );

                if (
                    !Number.isInteger(callerId) ||
                    callerId <= 0 ||
                    callerId === userId ||
                    !userExists(callerId)
                ) {
                    return;
                }

                io.to(
                    `user:${callerId}`
                ).emit(
                    "call_rejected",
                    {
                        userId
                    }
                );
            }
        );

        /* =================================================
           ICE CANDIDATES
        ================================================= */

        socket.on(
            "ice_candidate",
            data => {
                const receiverId =
                    Number(
                        data?.receiverId
                    );

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0 ||
                    receiverId === userId ||
                    !userExists(receiverId)
                ) {
                    return;
                }

                io.to(
                    `user:${receiverId}`
                ).emit(
                    "ice_candidate",
                    {
                        senderId: userId,
                        candidate:
                            data?.candidate || null
                    }
                );
            }
        );

        /* =================================================
           END CALL
        ================================================= */

        socket.on(
            "end_call",
            data => {
                const receiverId =
                    Number(
                        data?.receiverId
                    );

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0 ||
                    receiverId === userId ||
                    !userExists(receiverId)
                ) {
                    return;
                }

                io.to(
                    `user:${receiverId}`
                ).emit(
                    "end_call",
                    {
                        userId
                    }
                );
            }
        );

        /* =================================================
           DISCONNECT
        ================================================= */

        socket.on(
            "disconnect",
            () => {
                console.log(
                    `User disconnected: ${socket.user.username}`
                );

                const count =
                    onlineUsers.get(userId) || 0;

                if (count <= 1) {
                    onlineUsers.delete(userId);
                } else {
                    onlineUsers.set(
                        userId,
                        count - 1
                    );
                }

                broadcastOnlineUsers();
            }
        );
    }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get(
    "/*splat",
    (req, res) => {
        res.sendFile(
            path.join(
                publicFolder,
                "index.html"
            )
        );
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(
            "Server error:",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        return res.status(500).json({
            error:
                "Internal server error."
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

server.listen(
    PORT,
    () => {
        console.log("");
        console.log(
            "================================"
        );
        console.log(
            "        TAVLIK IS RUNNING"
        );
        console.log(
            "================================"
        );
        console.log("");
        console.log(
            `Open: http://localhost:${PORT}`
        );
        console.log("");
    }
);
