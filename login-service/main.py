# login-service/main.py

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os

# ENV + DB
DB_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
SECRET_KEY = os.getenv("JWT_SECRET", "bankstack-secret-key")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SQLAlchemy
Base = declarative_base()
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

# App
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# DB Dep
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return get_user_by_email(db, payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

@app.get("/register", response_class=HTMLResponse)
def get_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def post_register(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="User exists")
    hashed_pw = pwd_context.hash(password)
    db.add(User(email=email, hashed_password=hashed_pw))
    db.commit()
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def post_login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.email})
    resp = RedirectResponse("/me", status_code=302)
    resp.set_cookie("access_token", token, httponly=True)
    return resp

@app.get("/me", response_class=HTMLResponse)
def me(request: Request, db: Session = Depends(get_db)):
    try:
        user = get_current_user(request, db)
        return templates.TemplateResponse("dashboard.html", {"request": request, "email": user.email})
    except:
        return RedirectResponse("/login", status_code=302)

