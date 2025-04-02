const express = require('express');
const router = express.Router();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

// Initialize database connection
const pool = new Pool({ connectionString: process.env.DB_URL });

// Rate limiting configuration
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts. Please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false
});

// Authentication middleware
const authenticateUser = (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.redirect('/login?error=Unauthorized');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.redirect('/login?error=Session expired. Please log in again.');
        }
        req.user = decoded;
        next();
    });
};

// Login routes
router.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../login.html'));
});

router.post('/login', loginLimiter, async (req, res) => {
    const { username, password, recaptchaToken } = req.body;

    if (!username || !password || !recaptchaToken) {
        return res.send('All fields are required.');
    }

    // Verify reCAPTCHA
    const recaptchaResponse = await axios.post(
        'https://www.google.com/recaptcha/api/siteverify',
        null,
        {
            params: {
                secret: process.env.RECAPTCHA_SECRET_KEY,
                response: recaptchaToken
            }
        }
    );

    if (!recaptchaResponse.data.success) {
        return res.send('Invalid reCAPTCHA. Please try again.');
    }

    try {
        const userResult = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.send('Invalid username/email or password.');
        }

        const user = userResult.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.send('Invalid username/email or password.');
        }

        // Generate JWT (valid for 15 minutes)
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        // Set JWT in cookie with warning time
        res.cookie('token', token, { 
            httpOnly: true, 
            secure: true,
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.redirect('/profile');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});

// Registration routes
router.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../register.html'));
});

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.send('All fields are required.');
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
        return res.send('Invalid email format.');
    }

    if (password.length < 8) {
        return res.send('Password must be at least 8 characters.');
    }

    try {
        const existingUser = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );

        if (existingUser.rows.length > 0) {
            return res.send('Username or Email already exists.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
            [username, email, hashedPassword]
        );

        res.send('Registration successful! You can now log in.');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});

// Logout route
router.get('/logout', (req, res) => {
    // Clear the token cookie with the same options as when it was set
    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
    });
    
    // Send a success message and redirect to login
    res.redirect('/login?message=You have been successfully logged out.');
});

module.exports = { router, authenticateUser }; 