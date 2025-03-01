const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';

const dbPath = process.env.RENDER ? '/opt/render/project/.db/trinetra.db' : path.join(__dirname, 'trinetra.db');
if (!fs.existsSync(path.dirname(dbPath))) fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        process.exit(1);
    }
    console.log('Connected to SQLite database at:', dbPath);
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')))`);
    db.run(`CREATE TABLE IF NOT EXISTS images (id INTEGER PRIMARY KEY AUTOINCREMENT, file_path TEXT NOT NULL, category TEXT NOT NULL, uploaded_at TEXT DEFAULT (datetime('now')))`);
    db.run(`CREATE TABLE IF NOT EXISTS live_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_details TEXT NOT NULL, youtube_link TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')))`);
    db.run(`CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL, replied INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')))`);
    db.run(`CREATE TABLE IF NOT EXISTS analytics (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, event_details TEXT, created_at TEXT DEFAULT (datetime('now')))`);

    const defaultAdmin = { username: 'admin', password: 'admin123' };
    bcrypt.hash(defaultAdmin.password, 10, (err, hash) => {
        if (err) return console.error('Error hashing default admin password:', err.message);
        db.get('SELECT * FROM admins WHERE username = ?', [defaultAdmin.username], (err, row) => {
            if (err) return console.error('Error checking default admin:', err.message);
            if (!row) {
                db.run('INSERT INTO admins (username, password) VALUES (?, ?)', [defaultAdmin.username, hash], (err) => {
                    if (err) console.error('Error inserting default admin:', err.message);
                    else console.log('Default admin created: admin/admin123');
                });
            }
        });
    });
});

const uploadsDir = process.env.RENDER ? '/opt/render/project/public/uploads' : path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { 
    setHeaders: (res, path) => {
        console.log(`Serving static file: ${path}`);
    }
}));

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'No token provided' });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, error: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${uuidv4()}_${file.originalname}`)
});
const upload = multer({ storage });

app.get('/api/images', (req, res) => {
    console.log('Received GET request for /api/images from:', req.ip);
    db.all('SELECT * FROM images ORDER BY uploaded_at DESC', [], (err, rows) => {
        if (err) {
            console.error('Error fetching images from DB:', err.message);
            return res.status(500).json({ success: false, error: 'Database error: ' + err.message });
        }
        console.log('Images fetched from DB:', rows);
        res.json(rows);
    });
});

app.get('/api/live_event', (req, res) => {
    console.log('Received GET request for /api/live_event from:', req.ip);
    db.get('SELECT * FROM live_events ORDER BY updated_at DESC LIMIT 1', [], (err, row) => {
        if (err) {
            console.error('Error fetching live event from DB:', err.message);
            return res.status(500).json({ success: false, error: 'Database error: ' + err.message });
        }
        console.log('Live event fetched from DB:', row);
        res.json(row || {});
    });
});

app.get('/api/contacts', authenticate, (req, res) => {
    db.all('SELECT * FROM contacts ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json(rows);
    });
});

app.post('/api/contact', (req, res) => {
    const { name, email, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ success: false, error: 'All fields are required' });
    db.run('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)', [name, email, message], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['contact_form', `Message from ${name}`]);
        res.json({ success: true });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Username and password are required' });
    db.get('SELECT * FROM admins WHERE username = ?', [username], (err, row) => {
        if (err || !row) return res.status(401).json({ success: false, error: 'Invalid credentials' });
        bcrypt.compare(password, row.password, (err, match) => {
            if (err || !match) return res.status(401).json({ success: false, error: 'Invalid credentials' });
            const token = jwt.sign({ id: row.id, username: row.username }, SECRET_KEY, { expiresIn: '1h' });
            db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['login', `Admin login: ${username}`]);
            res.json({ success: true, token });
        });
    });
});

app.post('/api/register', authenticate, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Username and password are required' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        db.run('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hash], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['register', `New admin: ${username}`]);
            res.json({ success: true });
        });
    });
});

app.post('/api/upload', authenticate, upload.single('image'), (req, res) => {
    const { category } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    const sharp = require('sharp');
    sharp(file.path)
        .resize({ width: 800 })
        .jpeg({ quality: 85 })
        .toFile(`${file.path}_resized.jpg`, (err) => {
            if (err) {
                console.error('Error resizing image:', err.message);
                return res.status(500).json({ success: false, error: err.message });
            }
            fs.unlinkSync(file.path);
            fs.renameSync(`${file.path}_resized.jpg`, file.path);
            const web_path = `/uploads/${file.filename}`;
            db.run('INSERT INTO images (file_path, category) VALUES (?, ?)', [web_path, category], function(err) {
                if (err) {
                    console.error('Error saving image to DB:', err.message);
                    return res.status(500).json({ success: false, error: err.message });
                }
                console.log('Image uploaded and saved to DB:', web_path);
                db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['upload', `Image uploaded: ${web_path}`]);
                res.json({ success: true, file_path: web_path });
            });
        });
});

app.delete('/api/delete_image/:id', authenticate, (req, res) => {
    const id = req.params.id;
    db.get('SELECT file_path FROM images WHERE id = ?', [id], (err, row) => {
        if (err || !row) return res.status(404).json({ success: false, error: 'Image not found' });
        fs.unlink(path.join(__dirname, 'public', row.file_path), (err) => {
            if (err) console.error('Error deleting file:', err.message);
            db.run('DELETE FROM images WHERE id = ?', [id], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['delete_image', `Image ID: ${id}`]);
                res.json({ success: true });
            });
        });
    });
});

app.post('/api/add_event', authenticate, (req, res) => {
    const { event_details, youtube_link } = req.body;
    if (!event_details || !youtube_link) return res.status(400).json({ success: false, error: 'Event details and YouTube link are required' });
    db.run('INSERT INTO live_events (event_details, youtube_link) VALUES (?, ?)', [event_details, youtube_link], function(err) {
        if (err) {
            console.error('Error saving event to DB:', err.message);
            return res.status(500).json({ success: false, error: err.message });
        }
        console.log('Event added to DB:', { event_details, youtube_link });
        db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['add_event', `Event: ${event_details}`]);
        res.json({ success: true });
    });
});

app.delete('/api/delete_event/:id', authenticate, (req, res) => {
    const id = req.params.id;
    db.run('DELETE FROM live_events WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['delete_event', `Event ID: ${id}`]);
        res.json({ success: true });
    });
});

app.get('/api/admins', authenticate, (req, res) => {
    db.all('SELECT id, username, created_at FROM admins', [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json(rows);
    });
});

app.put('/api/update_admin/:id', authenticate, (req, res) => {
    const id = req.params.id;
    const { username, password } = req.body;
    if (!username) return res.status(400).json({ success: false, error: 'Username is required' });
    if (password) {
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            db.run('UPDATE admins SET username = ?, password = ? WHERE id = ?', [username, hash, id], function(err) {
                if (err) return res.status(500).json({ success: false, error: err.message });
                db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['update_admin', `Admin ID: ${id}`]);
                res.json({ success: true });
            });
        });
    } else {
        db.run('UPDATE admins SET username = ? WHERE id = ?', [username, id], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['update_admin', `Admin ID: ${id}`]);
            res.json({ success: true });
        });
    }
});

app.delete('/api/delete_admin/:id', authenticate, (req, res) => {
    const id = req.params.id;
    db.run('DELETE FROM admins WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['delete_admin', `Admin ID: ${id}`]);
        res.json({ success: true });
    });
});

app.get('/api/events', authenticate, (req, res) => {
    db.all('SELECT * FROM live_events ORDER BY updated_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json(rows);
    });
});

app.post('/api/send_reply', authenticate, (req, res) => {
    const { contact_id } = req.body;
    if (!contact_id) return res.status(400).json({ success: false, error: 'Contact ID is required' });
    db.run('UPDATE contacts SET replied = 1 WHERE id = ?', [contact_id], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        db.run('INSERT INTO analytics (event_type, event_details) VALUES (?, ?)', ['send_reply', `Contact ID: ${contact_id}`]);
        res.json({ success: true });
    });
});

app.get('/api/analytics', authenticate, (req, res) => {
    db.all('SELECT * FROM analytics ORDER BY created_at DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json(rows);
    });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));