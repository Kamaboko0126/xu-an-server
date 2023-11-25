import uvicorn
from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from users import create_db
import sqlite3
import hashlib
import uuid
import yagmail
from mymail import myEmail, myPassword

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


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# your app code here


@app.get("/")
def home():
    return {"Data": "Test"}


@app.post("/adduser")
def create_user(user: User):
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
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                  (user.firstName, user.lastName, user.email, user.password, public_key, 0))

        send_email(user.email, 'Hello', 'http://127.0.0.1:8080/verify?email=' +
                   user.email + '&key=' + public_key)

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()

    return {"status": "Success"}


@app.post("/verify")
async def verify(data: VerifyData):
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
async def login(data: LoginData):
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
    if user and user['password'] == data.password:
        return {"status": "success"}
    else:
        return {"status": "wrong password"}


@app.get("/health")
def check_connect_health():
    return {"status": "Success"}


def send_email(to, subject, body):
    yag = yagmail.SMTP(myEmail, myPassword)
    yag.send(
        to=to,
        subject=subject,
        contents=body,
    )


if __name__ == "__main__":
    uvicorn.run(app, port=10000)
