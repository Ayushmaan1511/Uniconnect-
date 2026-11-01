# Uniconnect

Uniconnect is a full-stack educational community platform designed to connect students and administrators. It features a robust backend built with Node.js, Express, and SQLite, offering an intuitive environment for discussions, broadcasts, and assignment management.

## Features

- **User Authentication & Authorization**: Secure registration and login using JWT (JSON Web Tokens) stored in cookies. Role-based access control (Student and Admin).
- **User Profiles**: Users can manage their profiles, update bios, and upload profile pictures.
- **Discussion Forums**: Users can create topics and participate in discussion threads.
- **Broadcasts**: Administrators can publish important broadcasts/announcements to all users.
- **Assignments**: Students can upload and download assignment files seamlessly.
- **Security**: Integrates `helmet` for security headers, `express-rate-limit` to prevent brute-force attacks on authentication routes, and `bcryptjs` for secure password hashing.

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: SQLite3
- **Authentication**: JSON Web Tokens (JWT), bcryptjs
- **File Uploads**: Multer
- **Security**: Helmet, Express Rate Limit

## Installation and Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Kabir1218P/Uniconnect-.git
   cd Uniconnect-
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

   The server will start on `http://localhost:3000`.

## Directory Structure

- `server.js` - Main application entry point containing Express routes and DB initialization.
- `public/` - Static files (HTML, CSS, JS) served to the frontend.
- `uploads/` - Directory where uploaded assignments and avatars are stored.
- `unico.db` - SQLite database file generated automatically.

## API Endpoints

- **Auth**: `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`
- **Profile**: `/api/profile`, `/api/profile/avatar`
- **Topics**: `/api/topics`
- **Discussions**: `/api/discussions`
- **Broadcasts**: `/api/broadcasts`
- **Assignments**: `/api/assignments`

## License

ISC License
