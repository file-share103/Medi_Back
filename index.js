const express = require('express');
const cors = require('cors');
const path = require('path');
const db = require('./db');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Auth Dependencies
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET = 'mad-super-secret-key-123'; // In prod use ENV

// Middleware
app.use(cors({
    origin: true, // Allow any origin (reflects request origin)
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Global Error Handler to prevent crashes
process.on('uncaughtException', (err) => {
    console.error('UNCAUGHT EXCEPTION:', err);
});

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Routes Import (Will add later)
// const authRoutes = require('./routes/auth');
// app.use('/api/auth', authRoutes);

// Simple Test Route
app.get('/', (req, res) => {
    res.json({ message: 'Mad Auth API Running' });
});

app.get('/api/test', (req, res) => {
    res.json({ status: "Backend working fine ✅" });
});

// --- MIDDLEWARE (Moved to top) ---
const verifyToken = (req, res, next) => {
    let token;
    const header = req.headers['authorization'];
    if (header) {
        token = header.split(' ')[1];
    } else if (req.query.token) {
        token = req.query.token;
    }

    if (!token) return res.status(403).json({ error: 'No token' });

    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(500).json({ error: 'Failed to authenticate' });
        req.userId = decoded.id;
        req.userRole = decoded.role;
        // console.log(`[DEBUG] verifyToken: User ${req.userId} has role ${req.userRole}`);
        next();
    });
};

const verifyAdmin = (req, res, next) => {
    if (req.userRole !== 'admin' && req.userRole !== 'super-admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

const verifySuperAdmin = (req, res, next) => {
    if (req.userRole !== 'super-admin') {
        return res.status(403).json({ error: 'Super Admin access required' });
    }
    next();
};


// --- PASSWORD RESET & CHANGE SYSTEM ---

// 1. Initialize Table
db.run(`CREATE TABLE IF NOT EXISTS password_reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    status TEXT DEFAULT 'pending', -- pending, approved, rejected, completed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// 1. Request Password Reset (Public)
app.post('/api/auth/forgot-password-check', (req, res) => {
    const { email, flatNumber, mobile } = req.body;

    // Verify user exists with these exact details
    db.get('SELECT * FROM users WHERE email = ? AND flatNumber = ? AND mobile = ?',
        [email, flatNumber, mobile],
        (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!user) return res.status(404).json({ error: 'No user found with these details.' });

            // Check if there is already a pending or approved request
            db.get('SELECT * FROM password_reset_requests WHERE user_id = ? AND status IN ("pending", "approved")',
                [user.id],
                (err, request) => {
                    if (err) return res.status(500).json({ error: err.message });

                    if (request) {
                        // Return existing status
                        return res.json({
                            status: request.status,
                            message: request.status === 'approved'
                                ? 'Request approved! You can reset your password now.'
                                : 'Request already pending approval.'
                        });
                    }

                    // Create new request
                    db.run('INSERT INTO password_reset_requests (user_id) VALUES (?)', [user.id], function (err) {
                        if (err) return res.status(500).json({ error: err.message });
                        res.json({
                            status: 'pending',
                            message: 'Password reset request sent for admin approval.'
                        });
                    });
                });
        });
});

// 2. Confirm Reset (Public - Only if Approved)
app.post('/api/auth/reset-password-confirm', (req, res) => {
    const { email, flatNumber, mobile, newPassword } = req.body;

    // Verify user again
    db.get('SELECT * FROM users WHERE email = ? AND flatNumber = ? AND mobile = ?',
        [email, flatNumber, mobile],
        (err, user) => {
            if (err || !user) return res.status(401).json({ error: 'Invalid details or user not found.' });

            // Check for APPROVED request
            db.get('SELECT * FROM password_reset_requests WHERE user_id = ? AND status = "approved"',
                [user.id],
                (err, request) => {
                    if (err) return res.status(500).json({ error: err.message });
                    if (!request) return res.status(403).json({ error: 'No approved reset request found.' });

                    // Update User Password
                    bcrypt.hash(newPassword, 10, (err, hash) => {
                        if (err) return res.status(500).json({ error: err.message });

                        db.run('UPDATE users SET password = ? WHERE id = ?', [hash, user.id], (err) => {
                            if (err) return res.status(500).json({ error: err.message });

                            // Mark request as completed
                            db.run('UPDATE password_reset_requests SET status = "completed" WHERE id = ?', [request.id]);

                            res.json({ message: 'Password reset successfully! You can now login.' });
                        });
                    });
                });
        });
});

// 3. Admin: List Pending Requests
app.get('/api/admin/password-requests', verifyToken, verifyAdmin, (req, res) => {
    db.all(`SELECT r.*, u.fullName, u.email, u.flatNumber, u.mobile 
            FROM password_reset_requests r
            JOIN users u ON r.user_id = u.id
            WHERE r.status = 'pending'
            ORDER BY r.created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 3b. Admin: List Request History (All)
app.get('/api/admin/password-requests-history', verifyToken, verifyAdmin, (req, res) => {
    const { search } = req.query;
    let query = `SELECT r.*, u.fullName, u.email, u.flatNumber, u.mobile 
                 FROM password_reset_requests r
                 JOIN users u ON r.user_id = u.id
                 WHERE 1=1`; // 1=1 for easy appending

    // Optional: Filter by status if needed, but history usually implies all non-pending? 
    // Or just all. Let's do all for now, frontend can filter.

    const params = [];
    if (search) {
        query += ` AND (u.fullName LIKE ? OR u.email LIKE ? OR u.flatNumber LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ` ORDER BY r.created_at DESC`;

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 4. Admin: Approve/Reject Request
app.put('/api/admin/password-requests/:id', verifyToken, verifyAdmin, (req, res) => {
    const { status } = req.body; // 'approved' or 'rejected'

    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    db.run('UPDATE password_reset_requests SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `Request ${status}` });
    });
});

// 5. User: Change Password (Logged In)
app.post('/api/auth/change-password', verifyToken, (req, res) => {
    const { oldPassword, newPassword } = req.body;

    db.get('SELECT * FROM users WHERE id = ?', [req.userId], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });

        bcrypt.compare(oldPassword, user.password, (err, match) => {
            if (!match) return res.status(401).json({ error: 'Incorrect old password' });

            bcrypt.hash(newPassword, 10, (err, hash) => {
                if (err) return res.status(500).json({ error: err.message });

                db.run('UPDATE users SET password = ? WHERE id = ?', [hash, req.userId], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ message: 'Password changed successfully' });
                });
            });
        });
    });
});

// START SERVER
// START SERVER
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});

// Temporary Route Placeholders (We will split these out)
// -----------------------------------------------------

// --- AUTH ---
// Dependencies moved to top


// Admin Signup
app.post('/api/auth/admin-signup', (req, res) => {
    const { email, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });

        // Check if admin exists? Maybe allow multiple admins
        db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, hash, 'admin'], function (err) {
            if (err) return res.status(400).json({ error: 'Email already exists' });
            const token = jwt.sign({ id: this.lastID, role: 'admin' }, SECRET);
            res.json({ token, user: { id: this.lastID, email, role: 'admin' } });
        });
    });
});

// Seed Super Admin
const seedSuperAdmin = () => {
    const superAdminEmail = 'super-admin-dev@mediterranea.mumbai';
    const superAdminPassword = '#RaHUl110220026%';

    db.get('SELECT * FROM users WHERE email = ?', [superAdminEmail], (err, user) => {
        if (err) {
            console.error('Error checking for super admin:', err);
            return;
        }

        if (!user) {
            console.log('Seeding Super Admin...');
            bcrypt.hash(superAdminPassword, 10, (err, hash) => {
                if (err) {
                    console.error('Error hashing password:', err);
                    return;
                }
                db.run('INSERT INTO users (email, password, role, fullName) VALUES (?, ?, ?, ?)',
                    [superAdminEmail, hash, 'super-admin', 'Super Admin'],
                    (err) => {
                        if (err) console.error('Error creating super admin:', err);
                        else console.log('Super Admin created successfully');
                    }
                );
            });
        } else {
            console.log('Super Admin already exists');
        }
    });
};

/* 
 * RUN SEED ON START 
 * Wait for DB connection? setTimeout is a simple hack, better to export db connection promise or run inside db.serialize
 */
setTimeout(seedSuperAdmin, 1000);

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });

        bcrypt.compare(password, user.password, (err, match) => {
            if (!match) return res.status(401).json({ error: 'Invalid password' });

            const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '365d' });
            // Hide password
            const { password, ...userWithoutPass } = user;
            res.json({ token, user: userWithoutPass });
        });
    });
});
// --- USERS (Admin Only) ---
// Middleware moved to top


// List Users
app.get('/api/users', verifyToken, verifyAdmin, (req, res) => {
    db.all('SELECT * FROM users WHERE role NOT IN ("admin", "super-admin")', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Create User (Admin)
app.post('/api/users', verifyToken, verifyAdmin, (req, res) => {
    const { fullName, email, mobile, altMobile, flatNumber, familyMembers } = req.body;
    const tempPassword = Math.random().toString(36).slice(-8);

    bcrypt.hash(tempPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });

        db.run(`INSERT INTO users (fullName, email, password, mobile, altMobile, flatNumber, familyMembers) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [fullName, email, hash, mobile, altMobile, flatNumber, familyMembers],
            function (err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID, email, password: tempPassword }); // Return raw pass for admin to see once
            });
    });
});

// Update User Details (Admin)
app.put('/api/users/:id', verifyToken, verifyAdmin, (req, res) => {
    const { fullName, email, mobile, altMobile, flatNumber, familyMembers } = req.body;
    db.run(
        `UPDATE users SET fullName = ?, email = ?, mobile = ?, altMobile = ?, flatNumber = ?, familyMembers = ? WHERE id = ?`,
        [fullName, email, mobile, altMobile, flatNumber, familyMembers, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'User updated successfully' });
        }
    );
});

// Reset Password (Admin)
app.put('/api/users/:id/password', verifyToken, verifyAdmin, (req, res) => {
    const { newPassword } = req.body;
    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });
        db.run('UPDATE users SET password = ? WHERE id = ?', [hash, req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Password reset successfully' });
        });
    });
});

// Delete User
app.delete('/api/users/:id', verifyToken, verifyAdmin, (req, res) => {
    db.run('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'User deleted' });
    });
});

// --- FOLDERS ---
// List Folders
app.get('/api/folders', verifyToken, (req, res) => {
    db.all('SELECT * FROM folders', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Create Folder (Admin)
app.post('/api/folders', verifyToken, verifyAdmin, (req, res) => {
    const { name } = req.body;
    db.run('INSERT INTO folders (name) VALUES (?)', [name], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name });
    });
});

// Delete Folder (Admin)
app.delete('/api/folders/:id', verifyToken, verifyAdmin, (req, res) => {
    // Optional: Check if folder has files? For now, let's just delete the folder entry. 
    // Files with this folder_id will have it set to NULL if we didn't CASCADE, but SQLite default is restrict/no action unless configured.
    // Let's just delete the folder.
    db.run('DELETE FROM folders WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Folder deleted' });
    });
});

// --- FILES (Upload) ---
const multer = require('multer');
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'server/uploads/'), // Fix path to be absolute or relative to run command? Multer relative is relative to CWD.
    // If run from root: server/uploads. If run from server/: uploads.
    // Let's use path relative to __dirname in config? No, multer string is simplified. 
    // Best: use absolute path or consistent relative.
    // I set static to path.join(__dirname, 'uploads'). Let's match that.
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Upload File (Admin -> User)
app.post('/api/upload', verifyToken, verifyAdmin, upload.single('file'), (req, res) => {
    const { userId, folderId } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    // DB Store relative path or full url? Full URL is easier for frontend.
    // Store relative path /uploads/filename
    const fileUrl = `/uploads/${file.filename}`;

    db.run(`INSERT INTO files (user_id, folder_id, filename, originalName, path) VALUES (?, ?, ?, ?, ?)`,
        [userId, folderId || null, file.filename, file.originalname, fileUrl],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'File uploaded successfully' });
        });
});

// Get Files for Specific User (Admin)
app.get('/api/users/:id/files', verifyToken, verifyAdmin, (req, res) => {
    db.all(`SELECT files.*, folders.name as folderName 
            FROM files 
            LEFT JOIN folders ON files.folder_id = folders.id 
            WHERE user_id = ?`, [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Delete File (Admin)
app.delete('/api/files/:id', verifyToken, verifyAdmin, (req, res) => {
    // 1. Get file path from DB
    db.get('SELECT * FROM files WHERE id = ?', [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'File not found' });

        const filePath = path.join(__dirname, 'uploads', row.filename);

        // 2. Delete from DB
        db.run('DELETE FROM files WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            // 3. Delete from Disk (Optional but recommended)
            if (fs.existsSync(filePath)) {
                fs.unlink(filePath, (err) => {
                    if (err) console.error('Failed to delete file on disk:', err);
                });
            }
            res.json({ message: 'File deleted' });
        });
    });
});

// Get My Files (User)
app.get('/api/my-files', verifyToken, (req, res) => {
    // Left Join Folders to allow null folders if any
    db.all(`SELECT files.*, folders.name as folderName 
            FROM files 
            LEFT JOIN folders ON files.folder_id = folders.id 
            WHERE user_id = ?`, [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Download File
app.get('/api/files/:id/download', verifyToken, (req, res) => {
    const fileId = req.params.id;
    console.log(`[DEBUG] Download Request: FileID=${fileId}, UserID=${req.userId}, Role=${req.userRole}`);

    db.get('SELECT * FROM files WHERE id = ?', [fileId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'File not found' });

        // Authorization Check: User must own the file or be an Admin
        // Check for 'super-admin' as well if you have that role
        if (req.userRole !== 'admin' && req.userRole !== 'super-admin' && row.user_id !== req.userId) {
            console.log(`[DEBUG] Access Denied: FileOwner=${row.user_id}, RequestingUser=${req.userId}, Role=${req.userRole}`);
            return res.status(403).json({ error: 'Access denied' });
        }

        const filePath = path.join(__dirname, 'uploads', row.filename);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File contents missing on server' });
        }

        // Check if it's a preview request (inline) or download
        const isPreview = req.query.preview === 'true';
        if (isPreview) {
            res.sendFile(filePath);
        } else {
            res.download(filePath, row.originalName);
        }
    });
});

// --- ANNOUNCEMENTS ---
// Post Announcement (Admin)
app.post('/api/announcements', verifyToken, verifyAdmin, upload.single('image'), (req, res) => {
    const { title, body } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    db.run(`INSERT INTO announcements (title, body, image_path) VALUES (?, ?, ?)`,
        [title, body, imageUrl],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Announcement posted' });
        });
});

// Get Announcements (Public/User)
app.get('/api/announcements', verifyToken, (req, res) => {
    db.all('SELECT * FROM announcements ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Delete Announcement (Admin)
app.delete('/api/announcements/:id', verifyToken, verifyAdmin, (req, res) => {
    const annId = req.params.id;
    console.log('Attempting to delete announcement ID:', annId);

    db.get('SELECT * FROM announcements WHERE id = ?', [annId], (err, row) => {
        if (err) {
            console.error('DB Error finding announcement:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            console.error('Announcement not found for ID:', annId);
            return res.status(404).json({ error: 'Announcement not found' });
        }

        // Delete image if exists
        if (row.image_path) {
            try {
                const fileName = row.image_path.split('/').pop();
                const filePath = path.join(__dirname, 'uploads', fileName);
                console.log('Deleting associated image:', filePath);
                if (fs.existsSync(filePath)) {
                    fs.unlink(filePath, (err) => {
                        if (err) console.error('Failed to delete announcement image on disk:', err);
                    });
                }
            } catch (fileErr) {
                console.error('Error in file deletion logic:', fileErr);
            }
        }

        db.run('DELETE FROM announcements WHERE id = ?', [annId], function (err) {
            if (err) {
                console.error('DB Error deleting announcement:', err);
                return res.status(500).json({ error: err.message });
            }
            console.log('Announcement deleted successfully. Rows affected:', this.changes);
            res.json({ message: 'Announcement deleted' });
        });
    });
});

// Update Announcement (Admin)
app.put('/api/announcements/:id', verifyToken, verifyAdmin, (req, res) => {
    const { title, body } = req.body;
    db.run('UPDATE announcements SET title = ?, body = ? WHERE id = ?', [title, body, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Announcement updated' });
    });
});

// --- COMPLAINTS ---
// Initialize Table
db.run(`CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'Open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// Create Complaint (User)
app.post('/api/complaints', verifyToken, (req, res) => {
    const { title, description } = req.body;
    db.run('INSERT INTO complaints (user_id, title, description) VALUES (?, ?, ?)',
        [req.userId, title, description],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Complaint submitted', id: this.lastID });
        });
});

// Get My Complaints (User)
app.get('/api/my-complaints', verifyToken, (req, res) => {
    db.all('SELECT * FROM complaints WHERE user_id = ? ORDER BY created_at DESC', [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Get All Complaints (Admin)
app.get('/api/complaints', verifyToken, verifyAdmin, (req, res) => {
    db.all(`SELECT complaints.*, users.fullName, users.flatNumber, users.mobile 
            FROM complaints 
            JOIN users ON complaints.user_id = users.id 
            ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Update Complaint Status (Admin)
app.put('/api/complaints/:id', verifyToken, verifyAdmin, (req, res) => {
    const { status } = req.body; // 'Resolved', 'In Progress', 'Useless'
    db.run('UPDATE complaints SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Status updated' });
    });
});

// Delete Complaint (Admin)
app.delete('/api/complaints/:id', verifyToken, verifyAdmin, (req, res) => {
    db.run('DELETE FROM complaints WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Complaint deleted' });
    });
});

// --- HIGHLIGHTS (HERO SLIDER) ---
// Initialize Table
db.run(`CREATE TABLE IF NOT EXISTS highlights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Get All Highlights (Public/User)
app.get('/api/highlights', verifyToken, (req, res) => {
    db.all('SELECT * FROM highlights ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Create Highlight (Admin)
app.post('/api/highlights', verifyToken, verifyAdmin, upload.single('image'), (req, res) => {
    const { title } = req.body;
    const image_path = req.file ? `/uploads/${req.file.filename}` : null;

    if (!image_path) return res.status(400).json({ error: 'Image is required' });

    db.run('INSERT INTO highlights (title, image_path) VALUES (?, ?)', [title, image_path], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Highlight added', id: this.lastID, image_path });
    });
});

// Delete Highlight (Admin)
app.delete('/api/highlights/:id', verifyToken, verifyAdmin, (req, res) => {
    db.run('DELETE FROM highlights WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Highlight deleted' });
    });
});


// Get User Profile
app.get('/api/me', verifyToken, (req, res) => {
    db.get('SELECT * FROM users WHERE id = ?', [req.userId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'User not found' });
        const { password, ...user } = row;
        res.json(user);
    });
});

// --- ADMIN MANAGEMENT (Super Admin Only) ---
// List Admins
app.get('/api/admins', verifyToken, verifySuperAdmin, (req, res) => {
    console.log('[DEBUG] GET /api/admins called');
    db.all('SELECT id, email, role, fullName FROM users WHERE role = "admin"', [], (err, rows) => {
        if (err) {
            console.error('[DEBUG] GET /api/admins error:', err);
            return res.status(500).json({ error: err.message });
        }
        console.log(`[DEBUG] GET /api/admins returned ${rows.length} rows`);
        res.json(rows);
    });
});

// Create Admin
app.post('/api/admins', verifyToken, verifySuperAdmin, (req, res) => {
    const { email, password, fullName } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: err.message });

        db.run('INSERT INTO users (email, password, role, fullName) VALUES (?, ?, ?, ?)',
            [email, hash, 'admin', fullName],
            function (err) {
                if (err) return res.status(400).json({ error: 'Email already exists' });
                res.json({ id: this.lastID, email, role: 'admin', fullName });
            });
    });
});

// Delete Admin
app.delete('/api/admins/:id', verifyToken, verifySuperAdmin, (req, res) => {
    db.run('DELETE FROM users WHERE id = ? AND role = "admin"', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Admin deleted' });
    });
});
