require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

// Import routes
const { router: authRouter, authenticateUser } = require('./routes/auth');
const profileRouter = require('./routes/profile');
const indexRouter = require('./routes/index');

// Initialize Express app
const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// Routes
app.use('/', indexRouter);
app.use('/', authRouter);
app.use('/', authenticateUser, profileRouter);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
