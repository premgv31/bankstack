# account-service/main.py

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, Float, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt, JWTError
import os

# ENV
DB_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
SECRET_KEY = os.getenv("JWT_SECRET", "bankstack-secret-key")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# DB
Base = declarative_base()
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

# App
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    account_type = Column(String)
    balance = Column(Float, default=1000.0)

@app.on_event("startup")
def init():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_email(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse("<h3>Account Service is up!</h3>")

@app.get("/ui/account", response_class=HTMLResponse)
def account_ui(request: Request, db: Session = Depends(get_db)):
    email = get_email(request)
    account = db.query(Account).filter(Account.email == email).first()
    return templates.TemplateResponse("account.html", {"request": request, "account": account})

@app.post("/ui/account")
def create_account_ui(request: Request, account_type: str = Form(...), db: Session = Depends(get_db)):
    email = get_email(request)
    if not db.query(Account).filter(Account.email == email).first():
        acc = Account(email=email, account_type=account_type)
        db.add(acc)
        db.commit()
    return RedirectResponse("/ui/account", status_code=302)

