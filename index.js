const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const cron = require('node-cron');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const shortId = require('shortid');
const crypto = require('crypto'); // For generating API keys
const dotenv = require('dotenv');
const axios = require('axios'); // Ensure axios is imported
const fetch = require('node-fetch'); // Make sure to include this if you're using fetch

// Load environment variables from .env file
dotenv.config();

const SignupKey = process.env.SignupKey; // Use your environment variables
const LoginKey = process.env.LoginKey;
const PasteKey = process.env.PasteKey;

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

// Main route / Login
app.get(['/', '/paste'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'paste.html'));
});

// Serve pastes page
function checkAuthentication(req, res, next) {
    if (req.session && req.session.userId) {
        next(); // User is authenticated
    } else {
        res.redirect('/login_page'); // Redirect to login page
    }
}

app.get('/dashboard', checkAuthentication, (req, res) => {
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

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    apiKey: { type: String, unique: true },
    plan: { type: Number, default: 0, min: 0, max: 3 }, // Plan from 0 to 3
    apiUsage: { type: Number, default: 0 }, // Track daily usage
    lastRequestDate: { type: Date, default: Date.now } // Store last request date
});

const User = mongoose.model('User', userSchema);

// Function to generate a URL-safe API key
function generateApiKey() {
    return crypto.randomBytes(24) // Generate 24 random bytes
        .toString('base64') // Convert to Base64
        .replace(/\+/g, '-') // Replace '+' with '-'
        .replace(/\//g, '_') // Replace '/' with '_'
        .replace(/=+$/, ''); // Remove trailing '=' characters
}

app.post('/register', async (req, res) => {
    const { username, email, password, plan = 0, 'cf-turnstile-response': turnstileResponse } = req.body; // Destructure the Turnstile response

    // Validate required fields
    if (!username || !email || !password || !turnstileResponse) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    if (plan < 0 || plan > 3) {
        return res.status(400).json({ error: 'Invalid plan value. It should be between 0 and 3.' });
    }

    try {
        const ip = req.headers['cf-connecting-ip']; // Get IP address from header

        // Validate the token by calling the
        // "/siteverify" API endpoint.
        let formData = new FormData();
        formData.append("secret", SignupKey);
        formData.append("response", turnstileResponse);
        formData.append("remoteip", ip);

        const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        const result = await fetch(url, {
            body: formData,
            method: "POST",
        });
        
        const outcome = await result.json();
        
        if (!outcome.success) {
            return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
        }

        // Hash the password and create the user if CAPTCHA is successful
        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = generateApiKey();

        const user = new User({
            username,
            email,
            password: hashedPassword,
            apiKey,
            plan,
            apiUsage: 0,
            lastRequestDate: Date.now()
        });

        await user.save();
        res.status(201).json({
            message: 'User registered successfully',
            apiKey,
            plan: user.plan
        });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(409).json({ error: 'Username or email already exists.' });
        }
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'An error occurred during registration.' });
    }
});

// User login endpoint
app.post('/login', async (req, res) => {
    const { username, password, 'cf-turnstile-response': turnstileResponse } = req.body; // Destructure Turnstile response

    // Validate required fields
    if (!username || !password || !turnstileResponse) {
        return res.status(400).json({ error: 'Username, password, and CAPTCHA response are required.' });
    }

    try {
        const ip = req.headers['cf-connecting-ip']; // Get IP address from header

        // Validate the token by calling the
        // "/siteverify" API endpoint.
        let formData = new FormData();
        formData.append("secret", LoginKey);
        formData.append("response", turnstileResponse);
        formData.append("remoteip", ip);

        const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        const result = await fetch(url, {
            body: formData,
            method: "POST",
        });
        
        const outcome = await result.json();

        if (!outcome.success) {
            return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.', outcome});
        }

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
        console.error('Error during login:', err);
        res.status(500).json({ error: 'An error occurred during login.'});
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
    const { title, content, expiration_date, 'cf-turnstile-response': turnstileResponse } = req.body; // Destructure Turnstile response

    // Validate required fields
    if (!title || !content || !turnstileResponse) {
        return res.status(400).json({ error: 'Title, content, and CAPTCHA response are required.' });
    }

    try {
        const ip = req.headers['cf-connecting-ip']; // Get IP address from header

        // Validate the token by calling the
        // "/siteverify" API endpoint.
        let formData = new FormData();
        formData.append("secret", PasteKey);
        formData.append("response", turnstileResponse);
        formData.append("remoteip", ip);

        const url = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
        const result = await fetch(url, {
            body: formData,
            method: "POST",
        });
        
        const outcome = await result.json();

        if (!outcome.success) {
            return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
        }

        const author = req.session.userId; // Assuming user is logged in and userId is stored in session
        const paste = new Paste({ title, content, expiration_date, author });
        await paste.save();
        res.status(201).json(paste);
    } catch (err) {
        console.error('Error while creating the paste:', err);
        res.status(500).json({ error: 'An error occurred while creating the paste.' });
    }
});

app.get('/success', async (req, res) => {
    try {
        // Destructure and validate query parameters
        const { order, email } = req.query;

        if (!order || !email) {
            return res.status(400).json({
                status: 'error',
                message: 'Bad Request: Order ID and email are required.',
                code: 'MISSING_PARAMS'
            });
        }

        // Sanitize inputs to prevent injection attacks
        const sanitizedOrder = encodeURIComponent(order);
        const sanitizedEmail = encodeURIComponent(email);

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(decodeURIComponent(sanitizedEmail))) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid email format.',
                code: 'INVALID_EMAIL'
            });
        }

        // Fetch order details securely from the external API
        let response;
        try {
            response = await fetch(`https://sell.app/api/v2/invoices/${sanitizedOrder}`, {
                method: 'GET',
                headers: {
                    accept: 'application/json',
                    Authorization: `Bearer ${process.env.ApiKey}`,
                },
            });
        } catch (fetchError) {
            console.error('Fetch error:', fetchError);
            return res.status(502).json({
                status: 'error',
                message: 'Failed to connect to the external API.',
                code: 'API_CONNECTION_ERROR'
            });
        }

        if (!response.ok) {
            const errorMsg = await response.text();
            console.warn(`API responded with ${response.status}: ${errorMsg}`);
            return res.status(response.status).json({
                status: 'error',
                message: 'Failed to fetch order details.',
                code: 'API_ERROR',
                details: errorMsg
            });
        }

        let orderData;
        try {
            orderData = await response.json();
        } catch (jsonError) {
            console.error('Error parsing API response:', jsonError);
            return res.status(500).json({
                status: 'error',
                message: 'Invalid response format from the external API.',
                code: 'INVALID_API_RESPONSE'
            });
        }

        // Validate if the email matches the customer email from the order
        if (sanitizedEmail !== encodeURIComponent(orderData.gateway.data.customer_email)) {
            return res.status(403).json({
                status: 'error',
                message: 'Unauthorized: Email does not match the order.',
                code: 'EMAIL_MISMATCH'
            });
        }

        // Determine plan based on the product price
        const price = parseFloat(orderData.payment.gateway.data.total.base);
        const planMap = { 3.99: 1, 7.99: 2, 10.99: 3 };
        const plan = planMap[price];

        if (!plan) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid price for the order.',
                code: 'INVALID_PRICE'
            });
        }

        // Find the user based on the email
        let user;
        try {
            user = await User.findOne({ email: sanitizedEmail });
        } catch (dbError) {
            console.error('Database error:', dbError);
            return res.status(500).json({
                status: 'error',
                message: 'Database query failed.',
                code: 'DB_ERROR'
            });
        }

        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found.',
                code: 'USER_NOT_FOUND'
            });
        }

        // Update the user's plan and save
        try {
            user.plan = plan;
            await user.save();
        } catch (saveError) {
            console.error('Error saving user data:', saveError);
            return res.status(500).json({
                status: 'error',
                message: 'Failed to update user plan.',
                code: 'SAVE_ERROR'
            });
        }

        // Render the success page with relevant data
        res.render('success', { orderData, price, plan });

    } catch (error) {
        console.error('Unexpected error processing request:', error);
        res.status(500).json({
            status: 'error',
            message: 'An internal error occurred.',
            code: 'INTERNAL_SERVER_ERROR',
            details: (error.message, response.json),
        });
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
            res.json({ 
                username: user.username, 
                email: user.email, 
                apiKey: user.apiKey, 
                plan: user.plan,
                apiUsage: user.apiUsage,
                lastRequestDate: user.lastRequestDate
            });
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
