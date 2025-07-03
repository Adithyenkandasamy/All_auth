import os
from datetime import datetime, timedelta
from typing import Optional

import requests
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from app.database import get_session, init_db
from app.models import User as UserModel

# Load environment variables from .env file
load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change_this_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "")
LINKEDIN_REDIRECT_URI = os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:8000/linkedin/callback")
print(LINKEDIN_REDIRECT_URI, LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

app = FastAPI(title="JWT Auth + LinkedIn Link FastAPI App")

# CORS configuration
origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# SQLModel User table is defined in models.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_user_db(username: str, session: Session) -> Optional[UserModel]:
    stmt = select(UserModel).where(UserModel.username == username)
    return session.exec(stmt).first()

def authenticate_user_db(username: str, password: str, session: Session) -> Optional[UserModel]:
    user = get_user_db(username, session)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

# dependency
async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_db(username, session)
    if user is None:
        raise credentials_exception
    return user

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserIn(BaseModel):
    username: str
    password: str

class LinkedInProfile(BaseModel):
    id: str
    localizedFirstName: str
    localizedLastName: str

# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/register", status_code=201)
async def register(user_in: UserIn, session: Session = Depends(get_session)):
    if get_user_db(user_in.username, session):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user_in.password)
    db_user = UserModel(username=user_in.username, hashed_password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {"msg": "User registered successfully"}

@app.post("/api/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = authenticate_user_db(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/user/me")
async def read_current_user(current_user: UserModel = Depends(get_current_user)):
    return current_user

# ---------------------------------------------------------------------------
# LinkedIn OAuth Endpoints
# ---------------------------------------------------------------------------

def build_linkedin_oauth_url(state: str):
    scope = "openid%20profile%20email"  # URL-encoded scopes for LinkedIn OIDC
    return (
        "https://www.linkedin.com/oauth/v2/authorization?response_type=code"
        f"&client_id={LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={LINKEDIN_REDIRECT_URI}"  # already URL encoded in env
        f"&state={state}"
        f"&scope={scope}"
    )

@app.get("/api/linkedin/url")
async def linkedin_oauth_url(current_user: UserModel = Depends(get_current_user)):
    """Return the LinkedIn authorization URL so the frontend can redirect the browser."""
    return {"url": build_linkedin_oauth_url(current_user.username)}


@app.get("/linkedin/login")
async def linkedin_login(current_user: UserModel = Depends(get_current_user)):
    state = current_user.username  # simplistic CSRF prevention; store per-session in prod
    print(state)
    auth_url = build_linkedin_oauth_url(state)
    print(auth_url)
    return RedirectResponse(url=auth_url)

@app.get("/linkedin/callback")
async def linkedin_callback(request: Request, session: Session = Depends(get_session)):
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    user = get_user_db(state, session)  # we used username as state
    if not user:
        raise HTTPException(status_code=400, detail="Invalid state")

    # Exchange code for access token
    token_url = "https://www.linkedin.com/oauth/v2/accessToken"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.post(token_url, data=data, headers=headers, timeout=10)
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Error contacting LinkedIn token endpoint: {exc}") from exc
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to obtain LinkedIn access token: {response.text}")
    access_token = response.json().get("access_token")

    # Fetch user profile (optional but demonstrates linkage)
    try:
        profile_resp = requests.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Error contacting LinkedIn userinfo endpoint: {exc}") from exc
    if profile_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to fetch LinkedIn profile: {profile_resp.text}")
    profile_data = profile_resp.json()

    # Store in user record
    user.linkedin_access_token = access_token
    user.linkedin_id = profile_data.get("id")
    user.linkedin_verified = True
    session.add(user)
    session.commit()

    return {"msg": "LinkedIn account linked successfully", "linkedin_profile": profile_data}


# Alias route to support legacy redirect URI
@app.get("/auth/linkedin/callback")
async def linkedin_callback_alias(request: Request, session: Session = Depends(get_session)):
    """Support old redirect URI /auth/linkedin/callback by delegating to linkedin_callback."""
    return await linkedin_callback(request, session)


@app.on_event("startup")
def on_startup():
    init_db()
