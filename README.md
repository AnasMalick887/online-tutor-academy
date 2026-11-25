# Online Tutor Academy (OTA)

A web-based platform that connects students with verified tutors for one-to-one online lessons. Students search and book tutors, pay securely through escrow, attend a built-in live classroom, and submit assignments; tutors manage availability and earnings; administrators verify tutors and handle disputes.

**Live prototype:** https://online-tutor-academy.ai.studio/

## Features

- **Accounts:** sign-up with e-mail OTP verification, login with lock-out after 5 failed attempts, password reset, profiles
- **Tutor discovery:** search and filter by subject, level, price, rating, language and availability
- **Booking and payment:** 30/60/90-minute sessions, 10-minute slot hold, gateway payment held in escrow, free cancellation up to 24 hours before start
- **Live classroom:** video, audio, chat, screen sharing, shared whiteboard, session timer
- **Learning activities:** study material upload, assignments, grading with feedback
- **Reviews and notifications:** 1-5 star ratings, tutor replies, e-mail/SMS/in-app reminders
- **Admin console:** tutor approval, user management, disputes and refunds, reports (CSV/PDF)

## Tech Stack

> Update this section to match what you actually used.

| Layer | Technology |
|---|---|
| Front end | HTML5, CSS3, JavaScript |
| Back end | REST/JSON API |
| Database | Relational (PostgreSQL / MySQL) |
| Real-time | WebRTC, WebSockets |
| External services | Video API, payment gateway (sandbox), e-mail/SMS |

## Getting Started

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd online-tutor-academy

# 2. Install dependencies
<install command, e.g. npm install>

# 3. Configure environment variables
cp .env.example .env     # then fill in the values

# 4. Run the app
<run command, e.g. npm start>
```

Never commit real API keys. `.env` must be listed in `.gitignore`.

## Repository Structure

```
/docs    SRS (PDF), project proposal, final report
/src     Application source code
/tests   Test cases and test results
```

## Documentation

- Software Requirements Specification (IEEE Std 830-1998 structure), Version 1.0
- Project Proposal
- Final Project Report

## Team

| Name | Roll No. |
|---|---|
| Shiekh Muhammad Owais | CS-24116 |
| Anus Alam | CS-24119 |
| Anas Anwar Malick | CS-24124 |
| Abdullah Hamid | CS-24125 |

Department of Computer and Information Systems, NED University of Engineering and Technology.
