# Room Buddy Project

Room Buddy is a web application designed to help people find roommates for available spaces by allowing users to post and search for room advertisements online.

## Table of Contents
[Features](#features)
[Project Structure](#project-structure)
[Usage](#usage)
[Configuration](#configuration)
[Dependencies](#dependencies)

## Features
- User Registration and Login with Email Verification
- Password Reset Functionality
- Post and Search for Room Ads
- Filter Search Results by Various Criteria
- User Authentication and Authorization
- Image Upload for Room Ads

## Project Structure
The project has the following structure:
```
room_buddy/
│
├── app.py                 # Main application file
│
├── static/                # Static files (CSS, JS, images)
│   ├── css/
│   │   └── style.css      # CSS styles
│   ├── js/
│   │   └── script.js      # JavaScript files
│   ├── images/
│   │   └── logreg.png     # Background image for login/register page
│   └── upload/            # Directory for uploaded images
│
├── templates/             # HTML templates
    ├── index.html
    ├── login.html
    ├── register.html
    ├── postad.html
    ├── search.html
    ├── email_verification.html
    ├── recover_email.html
    ├── forgot_password.html
    └── reset_password.html
```

## Usage
1. **Register a new user:**
   Navigate to the registration page and create a new account. You will receive a confirmation email. Click the link in the email to confirm your account.

2. **Login:**
   Use your registered credentials to log in to the application.

3. **Post an ad:**
   Once logged in, navigate to the "Post Ad" page and fill in the details of the room you want to advertise. You can upload photos and provide all necessary details.

4. **Search for ads:**
   Use the search functionality on the main page to filter room ads based on your criteria.

## Configuration
The application configuration is handled in the `Config` class within `app.py`. Key settings include:

- `SECRET_KEY`: A secret key for session management and CSRF protection.
- `SQLALCHEMY_DATABASE_URI`: Database connection URI for MySQL.
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: Email server settings for sending verification and password reset emails.
- `UPLOAD_FOLDER`: Directory path for storing uploaded images.

## Dependencies
The application depends on several Python packages, which are listed in `requirements.txt`:

- Flask
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-Login
- Flask-Mail
- Werkzeug
- itsdangerous
- logging
