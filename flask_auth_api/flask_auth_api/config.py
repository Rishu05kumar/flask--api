# config.py
import os

class Config:
    SECRET_KEY = 'your-secret-key'  # used by Flask
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'  # SQLite database
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'your-jwt-secret-key'  # used by JWT
