"""
Session management for cyba-Inspector
"""

import json
import os
from datetime import datetime
from pathlib import Path
import uuid

class SessionManager:
    def __init__(self):
        self.sessions_dir = Path.home() / '.cyba-inspector' / 'sessions'
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        
    def create_session(self, target, name, profile='auto'):
        """Create a new enumeration session"""
        session_id = str(uuid.uuid4())[:8]
        session_data = {
            'id': session_id,
            'target': target,
            'name': name,
            'profile': profile,
            'status': 'active',
            'created': datetime.now().isoformat(),
            'updated': datetime.now().isoformat(),
            'findings': {},
            'notes': [],
            'completed_modules': [],
            'pending_modules': []
        }
        
        session_file = self.sessions_dir / f"{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        return session_id
    
    def get_session(self, session_id):
        """Get session data by ID"""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        
        with open(session_file, 'r') as f:
            return json.load(f)
    
    def update_session(self, session_id, data):
        """Update session data"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session.update(data)
        session['updated'] = datetime.now().isoformat()
        
        session_file = self.sessions_dir / f"{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session, f, indent=2)
        
        return True
    
    def list_sessions(self):
        """List all sessions"""
        sessions = []
        for session_file in self.sessions_dir.glob('*.json'):
            with open(session_file, 'r') as f:
                session = json.load(f)
                sessions.append({
                    'id': session['id'],
                    'target': session['target'],
                    'name': session['name'],
                    'profile': session['profile'],
                    'status': session['status'],
                    'created': session['created'][:10]  # Date only
                })
        
        return sorted(sessions, key=lambda x: x['created'], reverse=True)
    
    def add_finding(self, session_id, module, finding):
        """Add a finding to session"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        if module not in session['findings']:
            session['findings'][module] = []
        
        session['findings'][module].append({
            'timestamp': datetime.now().isoformat(),
            'data': finding
        })
        
        return self.update_session(session_id, session)
    
    def add_note(self, session_id, note):
        """Add a note to session"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        session['notes'].append({
            'timestamp': datetime.now().isoformat(),
            'note': note
        })
        
        return self.update_session(session_id, session)
    
    def mark_module_complete(self, session_id, module):
        """Mark a module as completed"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        if module not in session['completed_modules']:
            session['completed_modules'].append(module)
        
        if module in session['pending_modules']:
            session['pending_modules'].remove(module)
        
        return self.update_session(session_id, session)