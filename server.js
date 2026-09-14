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
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
        "JWT_SECRET must be at least 32 characters long."
    );
}

/* =========================================
   DATABASE
========================================= */

const dataFolder = path.join(__dirname, "data");

if (!fs.existsSync(dataFolder)) {
    fs.mkdirSync(dataFolder, { recursive: true });
}

const db = new Database(
    path.join(dataFolder, "talkora.db")
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");


/* =========================================
   DATABASE TABLES
========================================= */

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
        content TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(sender_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

        FOREIGN KEY(receiver_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS
    idx_messages_conversation
    ON messages(sender_id, receiver_id, id);
`);


/* =========================================
   SECURITY
========================================= */

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(
    express.json({
        limit: "10kb"
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


/* =========================================
   FRONTEND
========================================= */

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


/* =========================================
   TOKEN
========================================= */

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


/* =========================================
   AUTHENTICATION MIDDLEWARE
========================================= */

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
        authorization.substring(7);

    try {
        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        req.user = decoded;

        next();

    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired token."
        });
    }
}


/* =========================================
   VALIDATION
========================================= */

function validUsername(username) {
    return (
        typeof username === "string" &&
        /^[a-zA-Z0-9_]{3,30}$/.test(username)
    );
}

function validEmail(email) {
    return (
        typeof email === "string" &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
        email.length <= 254
    );
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        password.length <= 128
    );
}


/* =========================================
   REGISTER
========================================= */

app.post(
    "/api/auth/register",
    async (req, res) => {
        try {
            const {
                username,
                email,
                password
            } = req.body;

            const cleanUsername =
                typeof username === "string"
                    ? username.trim()
                    : "";

            const cleanEmail =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            if (
                !validUsername(cleanUsername) ||
                !validEmail(cleanEmail) ||
                !validPassword(password)
            ) {
                return res.status(400).json({
                    error:
                        "Username, email or password is invalid."
                });
            }

            const existing =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE username = ?
                    OR email = ?
                `).get(
                    cleanUsername,
                    cleanEmail
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
                db.prepare(`
                    INSERT INTO users
                    (
                        username,
                        email,
                        password_hash
                    )
                    VALUES (?, ?, ?)
                `).run(
                    cleanUsername,
                    cleanEmail,
                    passwordHash
                );

            const user = {
                id: Number(result.lastInsertRowid),
                username: cleanUsername
            };

            const token =
                createToken(user);

            res.status(201).json({
                user,
                token
            });

        } catch (error) {
            console.error(
                "Registration error:",
                error
            );

            res.status(500).json({
                error:
                    "Registration failed."
            });
        }
    }
);


/* =========================================
   LOGIN
========================================= */

app.post(
    "/api/auth/login",
    async (req, res) => {
        try {
            const {
                email,
                password
            } = req.body;

            const cleanEmail =
                typeof email === "string"
                    ? email.trim().toLowerCase()
                    : "";

            if (
                !validEmail(cleanEmail) ||
                typeof password !== "string"
            ) {
                return res.status(400).json({
                    error:
                        "Invalid email or password."
                });
            }

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE email = ?
                `).get(cleanEmail);

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

            res.json({
                user: publicUser,
                token
            });

        } catch (error) {
            console.error(
                "Login error:",
                error
            );

            res.status(500).json({
                error:
                    "Login failed."
            });
        }
    }
);


/* =========================================
   CURRENT USER
========================================= */

app.get(
    "/api/me",
    authenticate,
    (req, res) => {
        const user =
            db.prepare(`
                SELECT
                    id,
                    username,
                    created_at
                FROM users
                WHERE id = ?
            `).get(req.user.id);

        if (!user) {
            return res.status(404).json({
                error:
                    "User not found."
            });
        }

        res.json({
            user
        });
    }
);


/* =========================================
   GET USERS
========================================= */

app.get(
    "/api/users",
    authenticate,
    (req, res) => {
        const users =
            db.prepare(`
                SELECT
                    id,
                    username,
                    created_at
                FROM users
                WHERE id != ?
                ORDER BY username ASC
            `).all(req.user.id);

        res.json({
            users
        });
    }
);


/* =========================================
   SEARCH USERS
========================================= */

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
            db.prepare(`
                SELECT
                    id,
                    username,
                    created_at
                FROM users
                WHERE id != ?
                AND username LIKE ?
                ORDER BY username ASC
                LIMIT 30
            `).all(
                req.user.id,
                `%${query}%`
            );

        res.json({
            users
        });
    }
);


/* =========================================
   GET MESSAGE HISTORY
========================================= */

app.get(
    "/api/messages/:userId",
    authenticate,
    (req, res) => {
        const otherUserId =
            Number(req.params.userId);

        if (
            !Number.isInteger(otherUserId) ||
            otherUserId <= 0
        ) {
            return res.status(400).json({
                error:
                    "Invalid user ID."
            });
        }

        const otherUser =
            db.prepare(`
                SELECT id
                FROM users
                WHERE id = ?
            `).get(otherUserId);

        if (!otherUser) {
            return res.status(404).json({
                error:
                    "User not found."
            });
        }

        const messages =
            db.prepare(`
                SELECT
                    id,
                    sender_id,
                    receiver_id,
                    content,
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
            `).all(
                req.user.id,
                otherUserId,
                otherUserId,
                req.user.id
            );

        res.json({
            messages
        });
    }
);


/* =========================================
   SOCKET.IO AUTHENTICATION
========================================= */

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

            socket.user = decoded;

            next();

        } catch (error) {
            next(
                new Error(
                    "Invalid or expired token."
                )
            );
        }
    }
);


/* =========================================
   ONLINE USERS
========================================= */

const onlineUsers = new Map();

function broadcastOnlineUsers() {
    const ids =
        Array.from(
            onlineUsers.keys()
        );

    io.emit(
        "online_users",
        ids
    );
}


/* =========================================
   SOCKET CONNECTION
========================================= */

io.on(
    "connection",
    (socket) => {
        const userId =
            socket.user.id;

        console.log(
            `User connected: ${socket.user.username}`
        );

        socket.join(
            `user:${userId}`
        );

        if (!onlineUsers.has(userId)) {
            onlineUsers.set(
                userId,
                1
            );
        } else {
            onlineUsers.set(
                userId,
                onlineUsers.get(userId) + 1
            );
        }

        broadcastOnlineUsers();


        /* =====================================
           SEND MESSAGE
        ===================================== */

        socket.on(
            "send_message",
            (data, callback) => {
                try {
                    const receiverId =
                        Number(data?.receiverId);

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

                    if (
                        !content ||
                        content.length > 2000
                    ) {
                        return callback?.({
                            error:
                                "Message must contain between 1 and 2000 characters."
                        });
                    }

                    if (
                        receiverId === userId
                    ) {
                        return callback?.({
                            error:
                                "You cannot message yourself."
                        });
                    }

                    const receiver =
                        db.prepare(`
                            SELECT id
                            FROM users
                            WHERE id = ?
                        `).get(receiverId);

                    if (!receiver) {
                        return callback?.({
                            error:
                                "Receiver not found."
                        });
                    }

                    /* SAVE MESSAGE */

                    const result =
                        db.prepare(`
                            INSERT INTO messages
                            (
                                sender_id,
                                receiver_id,
                                content
                            )
                            VALUES (?, ?, ?)
                        `).run(
                            userId,
                            receiverId,
                            content
                        );

                    /* GET SAVED MESSAGE */

                    const message =
                        db.prepare(`
                            SELECT
                                id,
                                sender_id,
                                receiver_id,
                                content,
                                created_at
                            FROM messages
                            WHERE id = ?
                        `).get(
                            result.lastInsertRowid
                        );

                    /* SEND TO BOTH USERS */

                    io.to(
                        `user:${userId}`
                    )
                    .to(
                        `user:${receiverId}`
                    )
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


        /* =====================================
           TYPING START
        ===================================== */

        socket.on(
            "typing",
            (data) => {
                const receiverId =
                    Number(data?.receiverId);

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0
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


        /* =====================================
           TYPING STOP
        ===================================== */

        socket.on(
            "stop_typing",
            (data) => {
                const receiverId =
                    Number(data?.receiverId);

                if (
                    !Number.isInteger(receiverId) ||
                    receiverId <= 0
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


        /* =====================================
           DISCONNECT
        ===================================== */

        socket.on(
            "disconnect",
            () => {
                console.log(
                    `User disconnected: ${socket.user.username}`
                );

                const count =
                    onlineUsers.get(userId) || 0;

                if (count <= 1) {
                    onlineUsers.delete(
                        userId
                    );
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


/* =========================================
   PAGE FALLBACK
========================================= */

/*
   Express 5 does not use the old "*" wildcard
   route syntax here.

   This fallback comes AFTER all API routes,
   so normal API requests are not affected.
*/

app.use(
    (req, res) => {
        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);


/* =========================================
   ERROR HANDLER
========================================= */

app.use(
    (err, req, res, next) => {
        console.error(err);

        res.status(500).json({
            error:
                "Internal server error."
        });
    }
);


/* =========================================
   START TALKORA
========================================= */

server.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log("");
        console.log(
            "================================"
        );
        console.log(
            "       TALKORA IS RUNNING"
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