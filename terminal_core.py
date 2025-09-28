"""
Core terminal functionality for the Communications Terminal
Handles encryption, commands, and terminal-specific operations
"""
import os
import hashlib
from datetime import datetime
from flask import request
from flask_socketio import emit, join_room, leave_room
from flask_login import current_user
from app import db, socketio
from models import Channel, Message, ActiveConnection, SecurityEvent, User
import json

class TerminalCore:
    """Core terminal operations and security"""
    
    @staticmethod
    def get_default_channels():
        """Initialize the three default secure channels"""
        channels = [
            {
                'channel_number': 1,
                'name': 'GENERAL_COMMS',
                'description': 'General communications channel for standard operations',
                'security_level': 'STANDARD'
            },
            {
                'channel_number': 2,
                'name': 'SECURE_OPS',
                'description': 'Secure operations channel for classified communications',
                'security_level': 'CLASSIFIED'
            },
            {
                'channel_number': 3,
                'name': 'DEEP_NET',
                'description': 'Deep network channel for top secret operations',
                'security_level': 'TOP_SECRET'
            }
        ]
        return channels
    
    @staticmethod
    def initialize_channels():
        """Create default channels if they don't exist"""
        for channel_data in TerminalCore.get_default_channels():
            existing = Channel.query.filter_by(channel_number=channel_data['channel_number']).first()
            if not existing:
                channel = Channel(**channel_data)
                db.session.add(channel)
        db.session.commit()
    
    @staticmethod
    def log_security_event(event_type, severity='INFO', description=None, additional_data=None):
        """Log security events for monitoring"""
        event = SecurityEvent()
        event.event_type = event_type
        event.severity = severity
        event.description = description
        event.ip_address = TerminalCore.get_client_ip()
        event.user_id = current_user.id if current_user.is_authenticated else None
        event.additional_data = additional_data
        db.session.add(event)
        db.session.commit()
    
    @staticmethod
    def get_client_ip():
        """Get client IP address for security logging"""
        from flask import request
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            return request.environ['REMOTE_ADDR']
        else:
            return request.environ['HTTP_X_FORWARDED_FOR']
    
    @staticmethod
    def hash_user_agent(user_agent):
        """Hash user agent for privacy-preserving tracking"""
        return hashlib.sha256(user_agent.encode()).hexdigest()
    
    @staticmethod
    def format_timestamp():
        """Format timestamp in terminal style"""
        return datetime.utcnow().strftime('%H:%M %p UTC')
    
    @staticmethod
    def format_system_message(content, msg_type='SYSTEM'):
        """Format system messages for terminal display"""
        timestamp = TerminalCore.format_timestamp()
        return {
            'timestamp': timestamp,
            'user': 'SYSTEM',
            'content': content,
            'type': msg_type,
            'is_system': True
        }
    
    @staticmethod
    def format_user_message(user, content):
        """Format user messages for terminal display"""
        timestamp = TerminalCore.format_timestamp()
        return {
            'timestamp': timestamp,
            'user': user.get_display_name(),
            'content': content,
            'type': 'USER',
            'is_system': False
        }
    
    @staticmethod
    def validate_command(command):
        """Validate and parse terminal commands"""
        if not command.startswith('/'):
            return {'valid': False, 'error': 'Commands must start with /'}
        
        parts = command[1:].split()
        if not parts:
            return {'valid': False, 'error': 'Empty command'}
        
        cmd = parts[0].upper()
        args = parts[1:] if len(parts) > 1 else []
        
        valid_commands = ['HELP', 'STATUS', 'CHANNELS', 'JOIN', 'USERS', 'CLEAR', 'SECURITY', 'PING']
        
        if cmd not in valid_commands:
            return {'valid': False, 'error': f'Unknown command: {cmd}'}
        
        return {'valid': True, 'command': cmd, 'args': args}

class ChannelManager:
    """Manage channel operations and security"""
    
    @staticmethod
    def join_channel(user, channel_number, session_id):
        """Join a user to a channel with security checks"""
        channel = Channel.query.filter_by(channel_number=channel_number).first()
        if not channel:
            return {'success': False, 'error': f'Channel #{channel_number} not found'}
        
        # Check security clearance
        if not ChannelManager.check_security_clearance(user, channel):
            TerminalCore.log_security_event(
                'UNAUTHORIZED_ACCESS_ATTEMPT',
                'WARNING',
                f'User {user.get_display_name()} attempted to access {channel.name} without clearance'
            )
            return {'success': False, 'error': 'SECURITY CLEARANCE INSUFFICIENT'}
        
        # Check channel capacity
        active_count = ActiveConnection.query.filter_by(channel_id=channel.id).count()
        if active_count >= channel.max_users:
            return {'success': False, 'error': 'CHANNEL AT MAXIMUM CAPACITY'}
        
        # Remove from previous channels
        ChannelManager.leave_all_channels(user, session_id)
        
        # Join new channel
        connection = ActiveConnection()
        connection.user_id = user.id
        connection.session_id = session_id
        connection.channel_id = channel.id
        connection.ip_address = TerminalCore.get_client_ip()
        connection.user_agent = TerminalCore.hash_user_agent(request.headers.get('User-Agent', ''))
        db.session.add(connection)
        db.session.commit()
        
        # Join SocketIO room
        join_room(f'channel_{channel_number}')
        
        # Announce join
        join_msg = TerminalCore.format_system_message(
            f'>>> USER {user.get_display_name()} CONNECTED TO CHANNEL'
        )
        emit('message', join_msg, to=f'channel_{channel_number}')
        
        TerminalCore.log_security_event('CHANNEL_JOIN', 'INFO', f'User joined channel {channel_number}')
        
        return {'success': True, 'channel': channel}
    
    @staticmethod
    def leave_all_channels(user, session_id):
        """Remove user from all channels"""
        connections = ActiveConnection.query.filter_by(user_id=user.id, session_id=session_id).all()
        for conn in connections:
            leave_room(f'channel_{conn.channel.channel_number}')
            # Announce leave
            leave_msg = TerminalCore.format_system_message(
                f'>>> USER {user.get_display_name()} DISCONNECTED FROM CHANNEL'
            )
            emit('message', leave_msg, to=f'channel_{conn.channel.channel_number}')
            db.session.delete(conn)
        db.session.commit()
    
    @staticmethod
    def check_security_clearance(user, channel):
        """Check if user has required security clearance for channel"""
        clearance_levels = {
            'STANDARD': 1,
            'CLASSIFIED': 2,
            'TOP_SECRET': 3
        }
        
        user_level = clearance_levels.get(user.security_clearance, 1)
        required_level = clearance_levels.get(channel.security_level, 1)
        
        return user_level >= required_level
    
    @staticmethod
    def get_channel_users(channel_number):
        """Get list of users in a channel"""
        channel = Channel.query.filter_by(channel_number=channel_number).first()
        if not channel:
            return []
        
        connections = ActiveConnection.query.filter_by(channel_id=channel.id).all()
        users = []
        for conn in connections:
            users.append({
                'name': conn.user.get_display_name(),
                'clearance': conn.user.security_clearance,
                'connected_at': conn.connected_at.strftime('%H:%M UTC')
            })
        return users

class MessageHandler:
    """Handle message encryption, storage, and delivery"""
    
    @staticmethod
    def send_message(user, channel_number, content):
        """Send an encrypted message to a channel"""
        channel = Channel.query.filter_by(channel_number=channel_number).first()
        if not channel:
            return {'success': False, 'error': 'Channel not found'}
        
        # Check if user is in channel
        connection = ActiveConnection.query.filter_by(
            user_id=user.id,
            channel_id=channel.id
        ).first()
        
        if not connection:
            return {'success': False, 'error': 'User not connected to channel'}
        
        # Create and encrypt message
        message = Message()
        message.channel_id = channel.id
        message.user_id = user.id
        message.ip_address = TerminalCore.get_client_ip()
        message.user_agent_hash = TerminalCore.hash_user_agent(request.headers.get('User-Agent', ''))
        message.set_content(content)
        db.session.add(message)
        db.session.commit()
        
        # Format for display
        formatted_msg = TerminalCore.format_user_message(user, content)
        
        # Emit to channel
        emit('message', formatted_msg, to=f'channel_{channel_number}')
        
        return {'success': True, 'message': formatted_msg}
    
    @staticmethod
    def get_channel_history(channel_number, limit=50):
        """Get recent message history for a channel"""
        channel = Channel.query.filter_by(channel_number=channel_number).first()
        if not channel:
            return []
        
        messages = Message.query.filter_by(channel_id=channel.id)\
                                .order_by(Message.timestamp.desc())\
                                .limit(limit).all()
        
        history = []
        for msg in reversed(messages):
            if msg.is_system_message:
                history.append(TerminalCore.format_system_message(msg.get_content()))
            else:
                history.append(TerminalCore.format_user_message(msg.user, msg.get_content()))
        
        return history