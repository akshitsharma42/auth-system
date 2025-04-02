# Authentication Application

A secure authentication system built with Node.js, Express, and PostgreSQL, featuring rate limiting, session management, and reCAPTCHA integration.

## Features

- 🔐 Secure user authentication with JWT
- 📝 User registration with email validation
- 🔒 Password hashing using bcrypt
- 🛡️ Rate limiting for login attempts
- ⏰ Session management with expiry warnings
- 🤖 reCAPTCHA integration for enhanced security
- 🎨 Modern and responsive UI
- 🔄 Auto-reload during development

## Prerequisites

- Node.js (>=14.0.0)
- PostgreSQL database
- reCAPTCHA keys (from Google reCAPTCHA)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd auth-app
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```env
DB_URL=your_postgresql_connection_string
JWT_SECRET=your_jwt_secret_key
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
```

4. Set up the PostgreSQL database:
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Running the Application

### Development Mode
```bash
npm run dev
```
This will start the server with nodemon for auto-reloading during development.

### Production Mode
```bash
npm start
```

The application will be available at `http://localhost:3000`






## Environment Variables

Required environment variables:
- `DB_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret key for JWT signing
- `RECAPTCHA_SITE_KEY`: Google reCAPTCHA site key
- `RECAPTCHA_SECRET_KEY`: Google reCAPTCHA secret key

