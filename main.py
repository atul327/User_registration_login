from fastapi import FastAPI, Header
from jose import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
from typing import Optional
import mysql.connector
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# For database connection
def get_connection():
    return mysql.connector.connect(
        host = 'localhost',
        user = 'root',
        password = 'atul@2006',
        database = 'backend_assignment'
    )


# Schemas Body
class UserRegister(BaseModel):
    username : str
    email : EmailStr
    password : str 
    # confPass : str


class UserLogin(BaseModel):
    email : EmailStr
    password : str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None

pwd_content = CryptContext(schemes=["bcrypt"])
def hash_password(password):
    return pwd_content.hash(password)

def verify_password(userPassword, db_pass):
    return pwd_content.verify(userPassword, db_pass)

SECRET_KEY="secret123"
ALGORITHM="HS256"

def create_token(data:dict):
    payload=data.copy()
    payload["exp"]=datetime.utcnow()+timedelta(hours=2)
    token=jwt.encode(payload,SECRET_KEY,algorithm=ALGORITHM)

    return token

# REGISTER 
@app.post("/register")
def register(user:UserRegister):

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email = %s",(user.email,))

    seen = cursor.fetchone()

    if seen:
        return {"message" : "Email already exist"}

    # if user.password != user.confPass:
    #     return {"message" : "Password not matched"}

    hashed=hash_password(user.password)

    sql="""INSERT INTO users(username,email,password,role) 
                VALUES(%s,%s,%s,%s)"""

    cursor.execute(sql,(user.username,user.email,hashed,"user"))
    conn.commit()

    return {"message":"User created"}
    
    


# LOGIN 

@app.post("/login")
def login(user:UserLogin):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    sql="SELECT * FROM users WHERE email=%s"

    cursor.execute(sql,(user.email,))
    db_user=cursor.fetchone()

    if not db_user:
        return {"error":"User not found"}

    if not verify_password(user.password,db_user["password"]):
        return {"error":"Wrong password"}

    token=create_token({"user_id":db_user["id"]})

    return {"access_token":token}


# CREATE TASK

@app.post("/tasks")
def create_task(task:TaskCreate,Authorization:str=Header()):

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if not Authorization:
        return {"error":"Token missing"}
    
    token=Authorization.split(" ")[1]
    payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])

    
    user_id=payload["user_id"]

    sql="INSERT INTO tasks(title,description,user_id) VALUES(%s,%s,%s)"

    cursor.execute(sql,(task.title,task.description,user_id))
    conn.commit()

    return {"message":"Task created"}


# GET TASKS 
@app.get("/tasks")
def get_tasks(Authorization:str=Header()):

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    if not Authorization:
        return {"error":"Token missing"}
    
    token=Authorization.split(" ")[1]

    payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
    user_id=payload["user_id"]

    sql="SELECT * FROM tasks WHERE user_id=%s"

    cursor.execute(sql,(user_id,))
    tasks=cursor.fetchall()

    return tasks