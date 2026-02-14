const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

db.all('SELECT id, email, role, fullName FROM users WHERE role = "admin"', [], (err, rows) => {
    if (err) { console.error(err); return; }
    console.log(`\nAdmins found by query: ${rows.length}\n`);
    console.log(JSON.stringify(rows));
});

db.close();
