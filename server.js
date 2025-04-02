require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cookieParser = require('cookie-parser');

// Initialize Express app and database connection
const app = express();
const pool = new Pool({ connectionString: process.env.DB_URL });

// Rate limiting configuration
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts. Please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false
});

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

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

// Routes

// Root route - Landing page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Login routes
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', loginLimiter, async (req, res) => {
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
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.post('/register', async (req, res) => {
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

// Profile route
app.get('/profile', authenticateUser, async (req, res) => {
    try {
        const userResult = await pool.query(
            'SELECT id, username, email, created_at FROM users WHERE id = $1',
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.redirect('/login?error=User not found.');
        }

        const user = userResult.rows[0];
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>User Profile</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f5f5f5;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                    }
                    .container {
                        background-color: white;
                        padding: 2rem;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                        width: 100%;
                        max-width: 500px;
                    }
                    h2 {
                        text-align: center;
                        color: #333;
                        margin-bottom: 1.5rem;
                        font-size: 2rem;
                    }
                    .profile-info {
                        background-color: #f8f9fa;
                        padding: 1.5rem;
                        border-radius: 6px;
                        margin-bottom: 1.5rem;
                        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
                    }
                    .info-group {
                        margin-bottom: 1.5rem;
                        padding-bottom: 1rem;
                        border-bottom: 1px solid #eee;
                        display: flex;
                        flex-direction: column;
                        gap: 0.5rem;
                    }
                    .info-group:last-child {
                        border-bottom: none;
                        margin-bottom: 0;
                        padding-bottom: 0;
                    }
                    .info-label {
                        font-weight: bold;
                        color: #666;
                        font-size: 0.9rem;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    .info-value {
                        color: #333;
                        font-size: 1.2rem;
                        font-weight: 500;
                    }
                    .logout-btn {
                        width: 100%;
                        padding: 0.75rem;
                        background-color: #dc3545;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 1rem;
                        transition: all 0.2s ease;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        font-weight: bold;
                    }
                    .logout-btn:hover {
                        background-color: #c82333;
                        transform: translateY(-1px);
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }
                    .session-warning {
                        text-align: center;
                        color: #856404;
                        background-color: #fff3cd;
                        padding: 0.75rem;
                        border-radius: 4px;
                        margin-bottom: 1.5rem;
                        display: none;
                        animation: fadeIn 0.5s ease-in;
                        font-weight: 500;
                    }
                    @keyframes fadeIn {
                        from { opacity: 0; transform: translateY(-10px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                    .profile-header {
                        text-align: center;
                        margin-bottom: 2rem;
                        padding-bottom: 1rem;
                        border-bottom: 2px solid #eee;
                    }
                    .profile-header h2 {
                        margin-bottom: 0.5rem;
                    }
                    .profile-header p {
                        color: #666;
                        font-size: 1.1rem;
                    }
                </style>
                <script>
                    function checkSessionExpiry() {
                        const token = document.cookie.split('; ').find(row => row.startsWith('token='));
                        if (token) {
                            try {
                                const tokenValue = token.split('=')[1];
                                const payload = JSON.parse(atob(tokenValue.split('.')[1]));
                                const expiryTime = payload.exp * 1000;
                                const currentTime = Date.now();
                                const timeLeft = expiryTime - currentTime;
                                
                                if (timeLeft <= 300000 && timeLeft > 0) { // 5 minutes or less remaining
                                    const warningDiv = document.getElementById('session-warning');
                                    warningDiv.style.display = 'block';
                                    warningDiv.textContent = 'Your session will expire in ' + Math.ceil(timeLeft/1000) + ' seconds. Please save your work.';
                                } else if (timeLeft <= 0) {
                                    // Redirect to login if session expired
                                    window.location.href = '/login?error=Session expired. Please log in again.';
                                }
                            } catch (error) {
                                console.error('Error checking session:', error);
                            }
                        }
                    }

                    // Check immediately when page loads
                    checkSessionExpiry();

                    // Check every minute
                    setInterval(checkSessionExpiry, 60000);
                </script>
            </head>
            <body>
                <div class="container">
                    <div class="profile-header">
                        <h2>Welcome, ${user.username}!</h2>
                        <p>Here's your profile information</p>
                    </div>
                    <div id="session-warning" class="session-warning"></div>
                    <div class="profile-info">
                        <div class="info-group">
                            <div class="info-label">User ID</div>
                            <div class="info-value">${user.id}</div>
                        </div>
                        <div class="info-group">
                            <div class="info-label">Username</div>
                            <div class="info-value">${user.username}</div>
                        </div>
                        <div class="info-group">
                            <div class="info-label">Email Address</div>
                            <div class="info-value">${user.email}</div>
                        </div>
                        <div class="info-group">
                            <div class="info-label">Member Since</div>
                            <div class="info-value">${new Date(user.created_at).toLocaleString('en-US', {
                                year: 'numeric',
                                month: 'long',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                hour12: true
                            })}</div>
                        </div>
                    </div>
                    <a href="/logout"><button class="logout-btn">Logout</button></a>
                </div>
            </body>
            </html>
        `);
        
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});

// Logout route
app.get('/logout', (req, res) => {
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
