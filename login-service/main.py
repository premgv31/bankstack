from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
from datetime import datetime, timedelta
import os

# Configuration
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "mypassword")
DB_HOST = os.getenv("DB_HOST", "bankstack-db")
DB_NAME = os.getenv("DB_NAME", "bankstack")
DB_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"

SECRET_KEY = "bankstack-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# DB setup
Base = declarative_base()
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI()

class JWTValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in ["/login", "/register", "/forgot-password", "/static", "/"]:
            return await call_next(request)

        token = request.cookies.get("access_token")
        if not token:
            return RedirectResponse("/login")
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user_email = payload.get("sub")
        except JWTError:
            return RedirectResponse("/login?error=session_expired")

        response = await call_next(request)
        return response

# Add the middleware
app.add_middleware(JWTValidationMiddleware)

# FastAPI setup
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class LoginLog(Base):
    __tablename__ = "login_logs"
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    status = Column(String, nullable=False)  # success or fail

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = get_user_by_email(db, payload.get("sub"))
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def log_login_attempt(db: Session, email: str, ip: str, status: str):
    log = LoginLog(
        email=email,
        timestamp=datetime.utcnow().isoformat(),
        ip_address=ip,
        status=status
    )
    db.add(log)
    db.commit()

# Routes
@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse("<h2>BANKSTACK-PRO PREM Login Service is up!</h2>")

@app.get("/register", response_class=HTMLResponse)
def get_register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def post_register(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if get_user_by_email(db, email):
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = pwd_context.hash(password)
    db_user = User(email=email, hashed_password=hashed_pw)
    db.add(db_user)
    db.commit()
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def get_login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def post_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    db_user = get_user_by_email(db, email)
    client_ip = request.client.host or "unknown"

    if not db_user or not verify_password(password, db_user.hashed_password):
       log_login_attempt(db, email, client_ip, "fail")
       raise HTTPException(status_code=401, detail="Invalid credentials")
    log_login_attempt(db, email, client_ip, "success")
    token = create_access_token({"sub": db_user.email})
    response = RedirectResponse("/me", status_code=302)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/me", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    try:
        user = get_current_user(request, db)
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "email": user.email,
            "balance": "₹1,25,000.50",
            "transactions": [
                {"date": "2025-06-20", "desc": "ATM Withdrawal", "amount": "-₹2,000"},
                {"date": "2025-06-19", "desc": "Salary Credit", "amount": "+₹1,50,000"},
                {"date": "2025-06-18", "desc": "Netflix", "amount": "-₹499"}
            ]
        })
    except:
        return RedirectResponse("/login", status_code=302)

# Auto-create tables on startup
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("access_token")
    return response

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot-password")
def forgot_password_submit(email: str = Form(...), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Simulate sending email
    print(f"Reset link sent to: {email} — Token: MOCK_RESET_TOKEN")
    return HTMLResponse("<h3>Reset link sent to your email (mocked)</h3>")

