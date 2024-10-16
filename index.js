const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const cron = require('node-cron');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const shortId = require('shortid');

const app = express();
app.set('view engine', 'ejs');
const PORT = process.env.PORT || 3000;
const mongoAtlasUri = process.env.MONGO_ATLAS_URI;

mongoose.connect(mongoAtlasUri, { serverSelectionTimeoutMS: 3000 });
const db = mongoose.connection;
db.on('error', (error) => {
    console.error('MongoDB connection error:', error);
});

// Configure session middleware
app.use(session({
    secret: process.env.SECURITY_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }, // 14 days
    store: MongoStore.create({
        mongoUrl: mongoAtlasUri,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60 // 14 days
    }),
}));

// EJS template files
app.set('views', path.join(__dirname, 'views'));

// Middleware to parse JSON request body
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Support URL-encoded bodies

// Main route / Login
app.get(['/', '/login_page'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve registration page
app.get('/register_page', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Serve pastes page
function checkAuthentication(req, res, next) {
    if (req.session && req.session.userId) {
        next(); // User is authenticated
    } else {
        res.redirect('/login_page'); // Redirect to login page
    }
}

app.get('/pastes', checkAuthentication, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Define schema and model for pastes
const pasteSchema = new mongoose.Schema({
    _id: { type: String, default: shortId.generate },
    title: String,
    content: String,
    created_at: { type: Date, default: Date.now },
    expiration_date: Date,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Reference to User model
});

const Paste = mongoose.model('Paste', pasteSchema);

// Define schema and model for users
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// User registration endpoint
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(409).json({ error: 'Username or email already exists.' });
        }
        res.status(500).json({ error: 'An error occurred during registration.' });
    }
});

// User login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const user = await User.findOne({ username });

        // Check if user exists and password is correct
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // Set userId in session
        req.session.userId = user._id;

        // Send success response
        res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        res.status(500).json({ error: 'An error occurred during login.' });
    }
});

// Pastes auto-deletion logic
pasteSchema.statics.deleteExpiredPastes = async function() {
    try {
        const currentDate = new Date();
        await this.deleteMany({ expiration_date: { $lte: currentDate } }).exec();
        console.log('Expired pastes deleted successfully');
    } catch (err) {
        console.error('Error deleting expired pastes:', err);
    }
};

// REST API endpoints
app.post('/api/pastes', async (req, res) => {
    const { title, content, expiration_date } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required.' });
    }

    try {
        const author = req.session.userId;
        const paste = new Paste({ title, content, expiration_date, author });
        await paste.save();
        res.status(201).json(paste);
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while creating the paste.' });
    }
});

app.get('/api/pastes', async (req, res) => {
    try {
        const userId = req.session.userId;
        const pastes = await Paste.find({ author: userId }).exec();
        res.json(pastes);
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while retrieving pastes.' });
    }
});

app.get('/api/pastes/:id', async (req, res) => {
    try {
        const paste = await Paste.findById(req.params.id).exec();
        if (!paste) {
            return res.status(404).json({ error: 'Paste not found.' });
        }
        res.json(paste);
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while retrieving the paste.' });
    }
});

app.get('/api/pastes/plain/:id', async (req, res) => {
    try {
        const paste = await Paste.findById(req.params.id).exec();
        if (!paste) {
            return res.status(404).send('Paste not found'); // Send plain text for 404
        }

        // Set the content type to plain text and send the paste content
        res.set('Content-Type', 'text/plain');
        res.send(paste.content); // Assuming 'content' is the field that contains the paste text
    } catch (err) {
        res.status(500).send(err.message); // Send plain text error message
    }
});

app.get('/api/pastes/:id/page', async (req, res) => {
    try {
        const paste = await Paste.findById(req.params.id).exec();
        if (!paste) {
            return res.status(404).json({ error: 'Paste not found.' });
        }
        const author = await User.findById(paste.author).exec();
        paste.author = author;
        res.render('paste', { paste });
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while retrieving the paste.' });
    }
});

app.put('/api/pastes/:id', async (req, res) => {
    const { title, content, expiration_date } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required.' });
    }

    try {
        const updatedPaste = await Paste.findByIdAndUpdate(req.params.id, { title, content, expiration_date }, { new: true }).exec();
        if (!updatedPaste) {
            return res.status(404).json({ error: 'Paste not found.' });
        }
        res.json(updatedPaste);
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while updating the paste.' });
    }
});

app.delete('/api/pastes/:id', async (req, res) => {
    try {
        const deletedPaste = await Paste.findByIdAndDelete(req.params.id).exec();
        if (!deletedPaste) {
            return res.status(404).json({ error: 'Paste not found.' });
        }
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: 'An error occurred while deleting the paste.' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

app.get('/current_user', async (req, res) => {
    if (req.session && req.session.userId) {
        try {
            const user = await User.findById(req.session.userId).exec();
            res.json(user);
        } catch (err) {
            res.status(500).json({ error: 'An error occurred while retrieving the user.' });
        }
    } else {
        res.status(401).json({ error: 'Not logged in.' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);

    // Schedule the auto-deletion task to run every hour
    cron.schedule('0 * * * *', async () => {
        console.log('Running auto-deletion task...');
        await Paste.deleteExpiredPastes();
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error occurred:', err.stack);
    res.status(500).json({ error: 'Something broke!' });
});

module.exports = app;
