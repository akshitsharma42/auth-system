const express = require('express');
const router = express.Router();
const { Pool } = require('pg');

// Initialize database connection
const pool = new Pool({ connectionString: process.env.DB_URL });

// Profile route
router.get('/profile', async (req, res) => {
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

module.exports = router; 