
/* =====================================================
   VISIT RWANDA GUIDE WEBSITE
   COMPLETE NODE.JS + EXPRESS + MYSQL BACKEND
   ===================================================== */

require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStoreFactory = require("express-mysql-session");
const multer = require("multer");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");

const path = require("path");
const fs = require("fs");

// =====================================================
// 1. CHECK CONFIGURATION
// =====================================================

const requiredSettings = [
    "DB_NAME",
    "SESSION_SECRET"
];

for (const setting of requiredSettings) {
    if (!process.env[setting]) {
        throw new Error(`Missing ${setting} in .env file`);
    }
}

if (
    process.env.NODE_ENV === "production" &&
    (!process.env.ADMIN_PASSWORD ||
     process.env.SESSION_SECRET.length < 32)
) {
    throw new Error("Set a strong admin password and session secret.");
}

// =====================================================
// 2. CREATE EXPRESS APP
// =====================================================

const app = express();

const PORT = process.env.PORT || 3000;

const frontendPath = path.join(__dirname, "../frontend");
const uploadPath = path.join(__dirname, "uploads");

fs.mkdirSync(uploadPath, { recursive: true });

app.disable("x-powered-by");

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

app.use(helmet({
    // Allows existing pages with inline CSS/JS to keep working.
    // Configure a strict Content Security Policy before deployment.
    contentSecurityPolicy: false
}));

app.use(cors({
    origin: process.env.FRONTEND_ORIGIN || "http://localhost:3000",
    credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(morgan("dev"));

// =====================================================
// 3. MYSQL DATABASE CONNECTION
// =====================================================

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// =====================================================
// 4. CREATE DATABASE TABLES
// =====================================================

async function createTables() {

    await db.query(`
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            email VARCHAR(150) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS content (
            id INT AUTO_INCREMENT PRIMARY KEY,
            page VARCHAR(50) NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            location VARCHAR(255),
            district VARCHAR(100),
            category VARCHAR(100),
            image_path VARCHAR(500),
            video_path VARCHAR(500),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(150) NOT NULL,
            email VARCHAR(150) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    console.log("Database tables are ready.");
}

// =====================================================
// 5. CREATE FIRST ADMINISTRATOR
// =====================================================

async function createFirstAdmin() {

    const [admins] = await db.query(
        "SELECT id FROM admins LIMIT 1"
    );

    if (admins.length > 0) {
        console.log("Administrator account already exists.");
        return;
    }

    const username = process.env.ADMIN_USERNAME;
    const email = process.env.ADMIN_EMAIL;
    const password = process.env.ADMIN_PASSWORD;

    if (!username || !email || !password) {
        console.log("No initial admin created. Set ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD in .env.");
        return;
    }

    if (password.length < 12) {
        throw new Error("Initial admin password must be at least 12 characters.");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await db.execute(
        `INSERT INTO admins (username, email, password_hash)
         VALUES (?, ?, ?)`,
        [username, email, passwordHash]
    );

    console.log("First administrator account created.");
}

// =====================================================
// 6. MYSQL SESSION STORE
// =====================================================

const MySQLStore = MySQLStoreFactory(session);

const sessionStore = new MySQLStore({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME,
    createDatabaseTable: true,
    schema: {
        tableName: "sessions"
    },
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: 24 * 60 * 60 * 1000
});

sessionStore.on("error", (error) => {
    console.error("Session store error:", error);
});

app.use(session({
    name: "visit_rwanda.sid",
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// =====================================================
// 7. AUTHENTICATION MIDDLEWARE
// =====================================================

function requireAdmin(req, res, next) {

    if (!req.session.admin) {
        return res.status(401).json({
            success: false,
            message: "Please log in as administrator."
        });
    }

    next();
}

// =====================================================
// 8. LOGIN RATE LIMITER
// =====================================================

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many login attempts. Try again later."
    }
});

// =====================================================
// 9. UPLOAD CONFIGURATION
// =====================================================

const allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "video/mp4",
    "video/webm",
    "video/quicktime"
];

const storage = multer.diskStorage({

    destination: (req, file, callback) => {
        callback(null, uploadPath);
    },

    filename: (req, file, callback) => {

        const extension = path.extname(file.originalname).toLowerCase();

        const safeName =
            Date.now() + "-" +
            require("crypto").randomBytes(8).toString("hex") +
            extension;

        callback(null, safeName);
    }
});

const upload = multer({

    storage: storage,

    limits: {
        fileSize: 100 * 1024 * 1024,
        files: 1
    },

    fileFilter: (req, file, callback) => {

        if (!allowedTypes.includes(file.mimetype)) {
            return callback(
                new Error("Only JPG, PNG, WEBP, GIF, MP4, WEBM and MOV files are allowed.")
            );
        }

        callback(null, true);
    }
});

// Serve uploaded media
app.use("/uploads", express.static(uploadPath));

// =====================================================
// 10. FRONTEND FILES
// =====================================================

app.use(express.static(frontendPath));

app.get("/", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
});

// =====================================================
// 11. BACKEND TEST
// =====================================================

app.get("/api/test", (req, res) => {

    res.json({
        success: true,
        message: "Visit Rwanda backend is working!"
    });
});

// =====================================================
// 12. DATABASE TEST
// =====================================================

app.get("/api/database-test", async (req, res) => {

    try {
        const [result] = await db.query("SELECT 1 AS connected");

        res.json({
            success: true,
            message: "MySQL database connected successfully!",
            result
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Database connection failed."
        });
    }
});

// =====================================================
// 13. ADMIN LOGIN
// =====================================================

app.post(
    "/api/admin/login",
    loginLimiter,
    [
        body("usernameOrEmail").trim().notEmpty(),
        body("password").notEmpty()
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        try {

            const { usernameOrEmail, password } = req.body;

            const [admins] = await db.execute(
                `SELECT * FROM admins
                 WHERE username = ? OR email = ?
                 LIMIT 1`,
                [usernameOrEmail, usernameOrEmail]
            );

            if (admins.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid username/email or password."
                });
            }

            const admin = admins[0];

            const passwordMatches = await bcrypt.compare(
                password,
                admin.password_hash
            );

            if (!passwordMatches) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid username/email or password."
                });
            }

            req.session.regenerate((error) => {

                if (error) {
                    return res.status(500).json({
                        success: false,
                        message: "Could not create login session."
                    });
                }

                req.session.admin = {
                    id: admin.id,
                    username: admin.username,
                    email: admin.email
                };

                req.session.save((saveError) => {

                    if (saveError) {
                        return res.status(500).json({
                            success: false,
                            message: "Could not save login session."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Login successful.",
                        admin: req.session.admin
                    });
                });
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message: "Login failed."
            });
        }
    }
);

// =====================================================
// 14. CHECK ADMIN LOGIN
// =====================================================

app.get("/api/admin/me", requireAdmin, (req, res) => {

    res.json({
        success: true,
        admin: req.session.admin
    });
});

// =====================================================
// 15. ADMIN LOGOUT
// =====================================================

app.post("/api/admin/logout", requireAdmin, (req, res) => {

    req.session.destroy((error) => {

        if (error) {
            return res.status(500).json({
                success: false,
                message: "Logout failed."
            });
        }

        res.clearCookie("visit_rwanda.sid");

        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});

// =====================================================
// 16. GET ALL PUBLIC CONTENT
// =====================================================

app.get("/api/content", async (req, res) => {

    try {

        const [results] = await db.query(
            "SELECT * FROM content ORDER BY created_at DESC"
        );

        res.json(results);

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Could not retrieve content."
        });
    }
});

// =====================================================
// 17. GET CONTENT BY PAGE
// =====================================================

app.get("/api/content/:page", async (req, res) => {

    try {

        const page = req.params.page.toLowerCase();

        if (!/^[a-z0-9-]{1,50}$/.test(page)) {
            return res.status(400).json({
                success: false,
                message: "Invalid page name."
            });
        }

        const [results] = await db.execute(
            `SELECT * FROM content
             WHERE page = ?
             ORDER BY created_at DESC`,
            [page]
        );

        res.json(results);

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Could not retrieve page content."
        });
    }
});

// =====================================================
// 18. ADMIN VIEW ALL CONTENT
// =====================================================

app.get("/api/admin/content", requireAdmin, async (req, res) => {

    try {

        const [results] = await db.query(
            "SELECT * FROM content ORDER BY created_at DESC"
        );

        res.json(results);

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Could not retrieve admin content."
        });
    }
});

// =====================================================
// 19. ADMIN ADD CONTENT
// =====================================================

app.post(
    "/api/admin/content",
    requireAdmin,
    [
        body("page").isIn([
            "home",
            "about",
            "culture",
            "toursite"
        ]),
        body("title").trim().notEmpty().isLength({ max: 255 }),
        body("description").optional({ nullable: true }).isString()
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        try {

            const {
                page,
                title,
                description,
                location,
                district,
                category,
                image_path,
                video_path
            } = req.body;

            const [result] = await db.execute(
                `INSERT INTO content
                (page, title, description, location, district,
                 category, image_path, video_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    page,
                    title,
                    description || "",
                    location || "",
                    district || "",
                    category || "",
                    image_path || null,
                    video_path || null
                ]
            );

            res.status(201).json({
                success: true,
                message: "Content added successfully.",
                id: result.insertId
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not add content."
            });
        }
    }
);

// =====================================================
// 20. ADMIN EDIT CONTENT
// =====================================================

app.put(
    "/api/admin/content/:id",
    requireAdmin,
    [
        body("page").isIn([
            "home",
            "about",
            "culture",
            "toursite"
        ]),
        body("title").trim().notEmpty().isLength({ max: 255 }),
        body("description").optional({ nullable: true }).isString()
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        try {

            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id < 1) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid content ID."
                });
            }

            const {
                page,
                title,
                description,
                location,
                district,
                category,
                image_path,
                video_path
            } = req.body;

            const [result] = await db.execute(
                `UPDATE content SET
                    page = ?,
                    title = ?,
                    description = ?,
                    location = ?,
                    district = ?,
                    category = ?,
                    image_path = ?,
                    video_path = ?
                 WHERE id = ?`,
                [
                    page,
                    title,
                    description || "",
                    location || "",
                    district || "",
                    category || "",
                    image_path || null,
                    video_path || null,
                    id
                ]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Content not found."
                });
            }

            res.json({
                success: true,
                message: "Content updated successfully."
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Could not update content."
            });
        }
    }
);

// =====================================================
// 21. ADMIN DELETE CONTENT
// =====================================================

app.delete(
    "/api/admin/content/:id",
    requireAdmin,
    async (req, res) => {

        try {

            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id < 1) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid content ID."
                });
            }

            const [result] = await db.execute(
                "DELETE FROM content WHERE id = ?",
                [id]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Content not found."
                });
            }

            res.json({
                success: true,
                message: "Content deleted successfully."
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message: "Could not delete content."
            });
        }
    }
);

// =====================================================
// 22. ADMIN UPLOAD IMAGE OR VIDEO
// =====================================================

app.post(
    "/api/admin/upload",
    requireAdmin,
    (req, res, next) => {

        upload.single("file")(req, res, (error) => {

            if (error) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            next();
        });
    },
    (req, res) => {

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: "Please select an image or video."
            });
        }

        const filePath = "/uploads/" + req.file.filename;

        res.json({
            success: true,
            message: "File uploaded successfully.",
            path: filePath,
            mediaType: req.file.mimetype.startsWith("image/")
                ? "image"
                : "video"
        });
    }
);

// =====================================================
// 23. SAVE CONTACT FORM MESSAGE
// =====================================================

app.post(
    "/api/messages",
    [
        body("name").trim().notEmpty().isLength({ max: 150 }),
        body("email").trim().isEmail().isLength({ max: 150 }),
        body("message").trim().notEmpty().isLength({ max: 5000 })
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }

        try {

            const { name, email, message } = req.body;

            await db.execute(
                `INSERT INTO messages (name, email, message)
                 VALUES (?, ?, ?)`,
                [name, email, message]
            );

            res.status(201).json({
                success: true,
                message: "Your message has been received."
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message: "Could not save your message."
            });
        }
    }
);

// =====================================================
// 24. ADMIN VIEW CONTACT MESSAGES
// =====================================================

app.get("/api/admin/messages", requireAdmin, async (req, res) => {

    try {

        const [results] = await db.query(
            "SELECT * FROM messages ORDER BY created_at DESC"
        );

        res.json(results);

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Could not retrieve messages."
        });
    }
});

// =====================================================
// 25. ADMIN DELETE CONTACT MESSAGE
// =====================================================

app.delete(
    "/api/admin/messages/:id",
    requireAdmin,
    async (req, res) => {

        try {

            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id < 1) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid message ID."
                });
            }

            const [result] = await db.execute(
                "DELETE FROM messages WHERE id = ?",
                [id]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Message not found."
                });
            }

            res.json({
                success: true,
                message: "Message deleted successfully."
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message: "Could not delete message."
            });
        }
    }
);

// =====================================================
// 26. API NOT FOUND
// =====================================================

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message: "API route not found."
    });
});

// =====================================================
// 27. GENERAL ERROR HANDLER
// =====================================================

app.use((error, req, res, next) => {

    console.error(error);

    res.status(500).json({
        success: false,
        message: "An unexpected server error occurred."
    });
});

// =====================================================
// 28. START BACKEND
// =====================================================

async function startServer() {

    try {

        await db.query("SELECT 1");

        console.log("MySQL database connected successfully!");

        await createTables();

        await createFirstAdmin();

        app.listen(PORT, () => {

            console.log("--------------------------------------");
            console.log("VISIT RWANDA GUIDE BACKEND");
            console.log("--------------------------------------");
            console.log(`Website: http://localhost:${PORT}`);
            console.log(`Admin: http://localhost:${PORT}/admin-login.html`);
            console.log(`API: http://localhost:${PORT}/api/test`);
            console.log("--------------------------------------");

        });

    } catch (error) {

        console.error("SERVER STARTUP FAILED:");
        console.error(error.message);

        process.exit(1);
    }
}

startServer();
