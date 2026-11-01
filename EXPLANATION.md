# UniConnect - Project Architecture & Explanation

This document provides a comprehensive overview of how the **UniConnect** project is structured, the technologies it uses, and how its various components work together to form a secure academic collaboration platform.

## 1. Project Overview
**UniConnect** is a full-stack web application designed for campus collaboration. It provides a centralized hub where students and administrators can interact through discussions, share assignments, and view campus-wide broadcasts.

## 2. Technology Stack
- **Frontend (Client-Side)**: 
  - **HTML5**: Defines the structure of the application (`index.html`, `login.html`, `dashboard.html`).
  - **CSS3 (`style.css`)**: Implements a highly modern, responsive "Glassmorphism" dark-mode UI. It features custom variables, flexbox/grid layouts, smooth animations, and custom modal/toast styling.
  - **Vanilla JavaScript (`script.js`)**: Handles all frontend logic, DOM manipulation, asynchronous API requests (`fetch`), and custom UI interactions without the need for heavy frameworks like React or Vue.
- **Backend (Server-Side)**: 
  - **Node.js & Express (`server.js`)**: Serves the static frontend files and provides a robust RESTful API.
  - **Authentication**: Uses `jsonwebtoken` (JWT) for secure, stateless sessions (stored in HTTP-only cookies) and `bcryptjs` for hashing user passwords securely.
  - **File Uploads**: Uses `multer` to handle multipart form data, saving assignments and profile pictures directly to the server's file system.
- **Database**: 
  - **SQLite (`unico.db`)**: A lightweight, file-based relational database used to store all persistent data.

## 3. Core Features & Data Flow

### Authentication & Authorization
- **Registration**: Users can sign up as either a `student` or an `admin`. Creating an admin account requires a specific environment-level invite code.
- **Login**: Verifies credentials and issues a JWT token as a cookie (`unico_token`). 
- **Middleware**: Most API routes are protected by a `requireAuth` middleware in `server.js` that verifies the JWT cookie before allowing access to the data.

### Dashboard & Navigation
- The frontend is built as a **Single Page Application (SPA)** hybrid. Once authenticated and on `dashboard.html`, navigation between sections (Overview, Profile, Discussions, etc.) is handled purely via JavaScript toggling CSS `display` properties, meaning page transitions are instant without requiring page reloads.

### Modules
1. **Overview**: A landing dashboard that provides quick statistics and recent system updates (pulled from broadcasts).
2. **Profile**: Users can update their bio, name, and upload a profile avatar. Avatars are saved in the `uploads/avatars/` directory.
3. **Discussions (Forum)**: 
   - Users can create **Topics**.
   - Under each topic, users can post **Discussion Messages**.
   - *Permissions*: Users can edit or delete their own topics and messages. Admins have global permission to delete/edit any post.
4. **Broadcasts**: A read-only announcement feed for students. Only users with the `admin` role can create, edit, or delete broadcasts.
5. **Assignments**: Users can upload files (PDFs, docs, etc.) via the frontend. `multer` intercepts these files, saves them in the `uploads/` directory, and records the file metadata in the database for others to download.
6. **CSIT GEU Integration**: A dedicated section utilizing an HTML `iframe` to seamlessly embed the external CSIT GEU website directly inside the UniConnect dashboard.

## 4. File Structure Breakdown

```text
/unico
├── server.js              # The core Node.js/Express server and API logic.
├── unico.db               # The SQLite database file (auto-generated).
├── package.json           # Node.js dependencies and run scripts.
├── uploads/               # Directory where assignments and avatars are stored.
└── public/                # Frontend static files served to the browser.
    ├── index.html         # Public landing page.
    ├── login.html         # Authentication interface (Login/Signup).
    ├── dashboard.html     # The main application shell for logged-in users.
    ├── style.css          # The master stylesheet for the entire application.
    └── script.js          # The master JavaScript file handling all frontend behavior.
```

## 5. UI/UX Highlights
- **Custom Modals**: Instead of using the browser's default (and often ugly) `alert()` or `prompt()` dialogues, the project implements a custom Promise-based modal system for confirming deletions or editing text.
- **Toast Notifications**: System feedback (e.g., "Assignment uploaded successfully" or "Error logging in") is delivered via sleek, animated toast notifications that slide in from the bottom corner and automatically disappear.
- **Security**: The backend implements `helmet` for secure HTTP headers and `express-rate-limit` to prevent brute-force attacks on the login endpoints.
