import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev")

    db_url = os.getenv("DATABASE_URL")

    if db_url:
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = db_url or "sqlite:///data.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False