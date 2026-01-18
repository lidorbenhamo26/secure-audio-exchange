import os
import hashlib
import secrets
import json
from typing import Optional

# Path to user database (JSON for demo)
USER_DB_PATH = os.path.join(os.path.dirname(__file__), 'users.json')

# Server-side pepper (must be kept secret, not in DB)
PEPPER =  b'your-very-secret-fixed-pepper-32bytes!!'
class UserAuth:
    def __init__(self, db_path=USER_DB_PATH):
        self.db_path = db_path
        self._load_db()

    def _load_db(self):
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def _save_db(self):
        with open(self.db_path, 'w') as f:
            json.dump(self.users, f)

    def register(self, username: str, password: str) -> bool:
        if username in self.users:
            return False  # User exists
        salt = secrets.token_bytes(16).hex()
        hash_val = self._hash_password(password, salt)
        self.users[username] = {
            'salt': salt,
            'hash': hash_val
        }
        self._save_db()
        return True

    def authenticate(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        if not user:
            return False
        salt = user['salt']
        hash_val = self._hash_password(password, salt)
        return secrets.compare_digest(hash_val, user['hash'])

    def _hash_password(self, password: str, salt: str) -> str:
        # Hash = H(password || salt || pepper)
        data = password.encode() + bytes.fromhex(salt) + PEPPER
        return hashlib.sha256(data).hexdigest()

    def get_salt(self, username: str) -> Optional[str]:
        user = self.users.get(username)
        return user['salt'] if user else None

    def get_hash(self, username: str) -> Optional[str]:
        user = self.users.get(username)
        return user['hash'] if user else None

    def list_users(self):
        return list(self.users.keys())
