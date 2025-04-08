from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import memcache
from passlib.context import CryptContext
from preload_users import fake_users_db  # Pre-hashed user database

# --- App Initialization ---
app = FastAPI()
bearer = HTTPBearer()

# --- Security Settings ---
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Connect to Memcached ---
mc = memcache.Client(['memcached:11211'], debug=0)

# --- Preload users into Memcached on startup ---
for username, user in fake_users_db.items():
    mc.set(f"user:{username}", user)

# --- Pydantic Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str
    password: str

# --- Helper Functions ---
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_user(username: str) -> dict | None:
    user = mc.get(f"user:{username}")
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Routes ---
@app.post("/token", response_model=Token)
async def login(form: LoginRequest):
    user = get_user(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
async def protected_route(user: dict = Depends(get_current_user)):
    return {"message": f"Hello, {user['full_name']}! This is a protected endpoint."}

@app.get("/protected2")
async def protected_admin_route(user: dict = Depends(get_current_user)):
    if not user.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"message": f"Welcome Admin {user['full_name']}! You have access to this route."}

# --- Run standalone ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
