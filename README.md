# Overview

A retro-themed secure communications terminal application that simulates a hacker-style command center with real-time messaging capabilities. The system provides three security-classified communication channels (General, Secure Ops, Deep Net) with different clearance levels. Users authenticate through Replit Auth and communicate through encrypted channels using SocketIO for real-time messaging, complete with terminal-style UI and ASCII art aesthetics.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Framework
- **Flask Application**: Main web framework with modular blueprint architecture
- **SQLAlchemy ORM**: Database abstraction layer with declarative base models
- **Flask-SocketIO**: Real-time bidirectional communication using WebSocket protocol
- **Eventlet**: Async mode for SocketIO to handle concurrent connections

## Authentication & Security
- **Replit OAuth Integration**: Third-party authentication using Flask-Dance OAuth consumer
- **Flask-Login**: Session management and user state handling
- **Rate Limiting**: DDoS protection with Flask-Limiter (200/day, 50/hour limits)
- **Message Encryption**: Cryptography.Fernet for end-to-end message encryption
- **Security Clearance System**: Three-tier access control (STANDARD, ELEVATED, ADMIN)

## Database Design
- **User Management**: Core user model with OAuth token storage for Replit Auth
- **Channel System**: Predefined secure channels with different security classifications
- **Message Storage**: Encrypted message persistence with channel associations
- **Connection Tracking**: Active connection monitoring and security event logging

## Real-time Communication
- **Multi-Channel Support**: Three default channels (GENERAL_COMMS, SECURE_OPS, DEEP_NET)
- **Socket Rooms**: Channel-based message broadcasting using SocketIO rooms
- **Connection Management**: Session-based user tracking with automatic cleanup
- **Message History**: Persistent chat history with encryption at rest

## Frontend Architecture
- **Terminal UI**: Retro hacker aesthetic with CSS animations and ASCII art
- **Real-time Updates**: JavaScript client for SocketIO communication
- **Responsive Design**: Mobile-friendly terminal interface
- **Status Indicators**: Live connection, channel, and encryption status display

## Security Features
- **Environment-based Configuration**: Critical settings via environment variables
- **Proxy Fix Middleware**: HTTPS URL generation for production deployment
- **CORS Protection**: Restricted origins for SocketIO connections
- **Session Security**: Permanent sessions with secure secret key management

# External Dependencies

## Authentication Services
- **Replit Auth**: Primary OAuth provider for user authentication and authorization

## Database
- **PostgreSQL**: Primary database (configured via DATABASE_URL environment variable)
- **SQLAlchemy**: ORM layer with connection pooling and health checks

## Real-time Infrastructure
- **SocketIO**: WebSocket communication with fallback transport options
- **Eventlet**: Async server runtime for concurrent connection handling

## Security & Encryption
- **Cryptography Library**: Fernet symmetric encryption for message security
- **Flask-Limiter**: Rate limiting with in-memory storage backend

## Frontend Libraries
- **Socket.IO Client**: JavaScript client library for real-time communication
- **Google Fonts**: Courier Prime font for authentic terminal appearance

## Environment Requirements
- **SESSION_SECRET**: Flask session encryption key
- **DATABASE_URL**: PostgreSQL connection string
- **ENCRYPTION_KEY**: Message encryption key (base64-encoded 32-byte key)
- **REPLIT_DOMAINS**: Allowed CORS origins for SocketIO connections
