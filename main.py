import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from users import create_db
import sqlite3
import hashlib
import uuid
import yagmail
from identifyinformation import MyEmail, MyPassword, MySecretKey
import jwt
import time
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

create_db()


class User(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    password: str


class VerifyData(BaseModel):
    email: str
    key: str


class LoginData(BaseModel):
    email: str
    password: str


class EditData(BaseModel):
    user_id: str
    password: str
    firstName: str
    lastName: str

class ChangeData(BaseModel):
    user_id: str
    oldPassword: str
    newPassword: str

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"status": "too many times"})

# your app code here


@app.get("/")
@limiter.limit("5/minute")
def home(request: Request):
    return {"Data": "Test"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

@app.post("/adduser")
@limiter.limit("5/minute")
def create_user(request: Request, user: User):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Insert a row of data
    c.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    existing_user = c.fetchone()
    if existing_user is not None:
        return {"status": "already registered"}
    else:
        # Generate a random UUID
        random_uuid = uuid.uuid4()
        # Create a SHA256 hash of the UUID
        public_key = hashlib.sha256(
            str(random_uuid).encode('utf-8')).hexdigest()
        # Generate a random UUID
        random_uuid = uuid.uuid4()
        # Convert the UUID to a string
        user_id = str(random_uuid)

        # Hash the user's password
        hashed_password = hash_password(user.password)

        c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (user_id, user.firstName, user.lastName, user.email, hashed_password, public_key, 0))

        send_email(user.email, 'Hello', 'http://127.0.0.1:8080/verify?email=' +
                   user.email + '&key=' + public_key)

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()

    return {"status": "Success"}


@app.post("/verify")
@limiter.limit("5/minute")
async def verify(request: Request, data: VerifyData):
    email = data.email
    public_key = data.key

    conn = sqlite3.connect('users.db')
    # Add this line to return query results as dictionaries
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Retrieve the user record from the database
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()

    # Check if the user is already verified
    if user and user['Verified']:
        return {"status": "verified"}

    # Check if the public keys match
    if user and user['publicKey'] == public_key:
        # Update the 'Verified' field to 1
        c.execute("UPDATE users SET Verified = 1 WHERE email = ?", (email,))
        conn.commit()
        return {"status": "success"}
    else:
        return {"status": "verification failed"}


@app.post('/login')
@limiter.limit("5/minute")
async def login(request: Request, data: LoginData):
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Retrieve the user record from the database
    c.execute("SELECT * FROM users WHERE email = ?", (data.email,))
    user = c.fetchone()

    # Check if the email exists
    if not user:
        return {"status": "invalid email"}

    # Check if the user is verified
    if not user['Verified']:
        return {"status": "verify yet"}

    # Check if the email and password match
    if user and pwd_context.verify(data.password, user['password']):
        payload = {
            'user_id': user['user_id'],
            'iat': time.time(),  # Add the issued at claim
        }
        token = jwt.encode(payload, MySecretKey, algorithm='HS256')
        return {
            "status": "success",
            "token": token,
            "firstname": user['firstName'],
            "lastname": user['lastName'],
            "userid": user['user_id'],
            "useremail": user['email']
        }
    else:
        return {"status": "wrong password"}


@app.get("/verify-token")
def verify_token(token: str, userid: str):
    try:
        payload = jwt.decode(token, MySecretKey, algorithms=["HS256"])
        if payload["user_id"] != userid:
            return {"status": "Token is invalid"}
        else:
            return {"status": "Token success verified"}
    except jwt.ExpiredSignatureError:
        return {"status": "Error", "detail": "Token is expired"}
    except jwt.InvalidTokenError:
        return {"status": "Error", "detail": "Token is invalid"}


@app.post("/edit")
@limiter.limit("5/minute")
async def update_user(request: Request, data: EditData):
    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    # Check if the password is correct
    cur.execute("SELECT password FROM users WHERE user_id = ?",
                (data.user_id,))
    result = cur.fetchone()
    if not result or not pwd_context.verify(data.password, result[0]):
        return {"status": "wrong password"}

    # Update the firstName and lastName
    cur.execute("""
        UPDATE users
        SET firstName = ?, lastName = ?
        WHERE user_id = ?
    """, (data.firstName, data.lastName, data.user_id))

    # Commit the changes and close the connection
    conn.commit()

    # Fetch the updated firstName and lastName
    cur.execute(
        "SELECT firstName, lastName FROM users WHERE user_id = ?", (data.user_id,))
    result = cur.fetchone()

    conn.close()

    print(result[0],result[1])
    if result:
        return {"status": "success", "firstname": result[0], "lastname": result[1]}
    else:
        return {"status": "fail"}

@app.post("/change")
@limiter.limit("5/minute")
async def change_password(request: Request, data: ChangeData):
    # Connect to the SQLite database
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    # Check if the old password is correct
    cur.execute("SELECT password FROM users WHERE user_id = ?",
                (data.user_id,))
    result = cur.fetchone()
    if not result or not pwd_context.verify(data.oldPassword, result[0]):
        return {"status": "wrong password"}

    # Hash the new password
    hashed_new_password = pwd_context.hash(data.newPassword)

    # Update the password
    cur.execute("""
        UPDATE users
        SET password = ?
        WHERE user_id = ?
    """, (hashed_new_password, data.user_id))

    conn.commit()
    return {"status": "success"}

@app.get("/health")
def check_connect_health():
    return {"status": "Success"}


def send_email(to, subject, body):
    yag = yagmail.SMTP(MyEmail, MyPassword)
    yag.send(
        to=to,
        subject=subject,
        contents=body,
    )


if __name__ == "__main__":
    uvicorn.run(app, port=10000)
