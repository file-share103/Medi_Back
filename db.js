const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Ensure db directory exists (optional, root is fine)
// Use safe production path (Absolute path)
const dbPath = path.resolve(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

db.serialize(() => {
  // Users Table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    mobile TEXT,
    altMobile TEXT,
    flatNumber TEXT,
    familyMembers INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Folders Table (Admin created folders for structure - or per user?)
  // Requirement: "option for creating a folder then where the user want to upload the data"
  // It implies Admin creates folders globally or per user? 
  // "create a option for each admin to upload specific data for each specific user"
  // Let's make folders generic but linked to a user? Or global folders like "Bills"?
  // "give a saperate option for creating a folder then where the user want to upload the data"
  // Admin uploads data FOR specific user.
  // So: Admin -> Select User -> Select Folder (Create New?) -> Upload.
  // We'll treat Folders as simple Categories for now, stored in a table to be reusable or dynamic.
  db.run(`CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
  )`);
  // Seed default folders
  db.run(`INSERT OR IGNORE INTO folders (name) VALUES ('General'), ('Maintenance Bills'), ('Agreements'), ('Notices')`);

  // Files Table
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    folder_id INTEGER,
    filename TEXT,
    originalName TEXT,
    path TEXT,
    uploaded_by TEXT DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(folder_id) REFERENCES folders(id)
  )`);

  // Announcements Table
  db.run(`CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    body TEXT,
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Password Reset Requests Table
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    status TEXT DEFAULT 'pending', -- pending, approved, completed, rejected
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

module.exports = db;
