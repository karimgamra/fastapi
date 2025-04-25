import os
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timedelta, time
from typing import List, Optional
from bson.objectid import ObjectId
import bson.errors
import pymongo
from pymongo.errors import DuplicateKeyError, PyMongoError
import jwt
import logging
from dateutil.parser import parse
from dateutil.rrule import rrule, WEEKLY
import pytz

# Pydantic Models
class SubjectResponse(BaseModel):
    subject_id: str
    name: str
    teacher_id: str
    teacher_name: str
    class_name: str
    created_by: str
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginForm(BaseModel):
    id: str
    password: str
    role: str

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    id: str
    role: str

class UserInDB(User):
    hashed_password: str

class StudentCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    id: str
    speciality: str

class TeacherCreate(BaseModel):
    id: str
    name: str
    email: EmailStr
    password: str
    subjects: List[str]
    classes: List[str]

class EventCreate(BaseModel):
    title: str
    event_type: str
    subject_id: str
    teacher_id: str
    class_name: str
    start_time: datetime
    end_time: datetime
    recurrence: Optional[str] = None
    recurrence_end: Optional[datetime] = None
    location: Optional[str] = None

class EventResponse(BaseModel):
    message: str
    event_ids: List[str]

class SubjectCreate(BaseModel):
    name: str
    teacher_id: str
    class_name: str

class AttendanceCreate(BaseModel):
    student_id: str
    subject_id: str
    event_id: str
    date: datetime
    status: str

class ScheduleResponse(BaseModel):
    class_name: str
    subject_name: str
    subject_id: Optional[str]
    teacher_id: str
    teacher_name: str

class CalendarEntryResponse(BaseModel):
    entry_id: str
    day_of_week: str
    start_time: str
    end_time: str
    schedules: List[ScheduleResponse]
    recurrence_end: Optional[datetime]
    created_by: str
    created_at: datetime

class ClassSchedule(BaseModel):
    class_name: str
    subject_name: str
    teacher_id: str

class CalendarEntry(BaseModel):
    day_of_week: str
    start_time: str
    end_time: str
    schedules: List[ClassSchedule]
    recurrence_end: Optional[datetime] = None

# FastAPI App Setup
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URI)
db = client.get_database("school")  # Explicitly specify the database name
admins_collection = db.admins
student_info_collection = db.student_info
teacher_info_collection = db.teacher_info
subjects_collection = db.subjects
events_collection = db.events
attendance_collection = db.attendance
calendar_collection = db.calendar

# JWT Configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12, deprecated="auto")

# Global Sets for Validation
valid_student_ids = set()
valid_teacher_ids = set()

# Valid Days
VALID_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# JWT Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Password Hashing Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Dependency for Admin Access
async def get_admin_user(id: str = Query(...), role: str = Query(...)):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    admin = await admins_collection.find_one({"id": id})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    return {"id": id, "role": role}

# Dependency for Teacher or Admin Access
async def get_teacher_or_admin(id: str = Query(...), role: str = Query(...)):
    if role not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="Teacher or admin access required")
    user = None
    if role == "teacher":
        user = await teacher_info_collection.find_one({"id": id})
    elif role == "admin":
        user = await admins_collection.find_one({"id": id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": id, "role": role}

# Sample Data Insertion (Only Admins)
async def insert_sample_admins():
    sample_admin = {
        "id": "admin001",
        "username": "admin",
        "email": "admin@university.com",
        "hashed_password": get_password_hash("adminpass")
    }
    try:
        await admins_collection.delete_many({})
        await admins_collection.insert_one(sample_admin)
        print("Successfully inserted sample admins")
    except Exception as e:
        print(f"Error inserting sample admins: {str(e)}")

# Startup Event (Indexes and Sample Data)
@app.on_event("startup")
async def startup_event():
    await subjects_collection.create_index([("name", 1), ("teacher_id", 1), ("class_name", 1)], unique=True)
    await attendance_collection.create_index([("student_id", 1), ("subject_id", 1), ("event_id", 1), ("date", 1)], unique=True)
    await student_info_collection.create_index([("id", 1)], unique=True)
    await teacher_info_collection.create_index([("id", 1)], unique=True)
    await events_collection.create_index([("subject_id", 1), ("start_time", 1)])
    await events_collection.create_index([("teacher_id", 1), ("start_time", 1)])
    await events_collection.create_index([("class_name", 1), ("start_time", 1)])
    await calendar_collection.create_index(
        [("day_of_week", 1), ("start_time", 1), ("end_time", 1), ("schedules.class_name", 1)],
        unique=True
    )

    await insert_sample_admins()

    global valid_student_ids, valid_teacher_ids
    valid_student_ids = {student["id"] for student in await student_info_collection.find({}, {"id": 1}).to_list(None)}
    valid_teacher_ids = {teacher["id"] for teacher in await teacher_info_collection.find({}, {"id": 1}).to_list(None)}

# Endpoints
@app.post("/register", response_model=Token)
async def register(user: User):
    if user.id in valid_student_ids:
        raise HTTPException(status_code=400, detail="Student ID already registered")
    
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    user_dict.pop("password")
    
    try:
        await student_info_collection.insert_one(user_dict)
        valid_student_ids.add(user.id)
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email or username already exists")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id, "role": "student"}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/admin/register")
async def admin_register(user: User, admin: dict = Depends(get_admin_user)):
    if user.role not in ["admin", "student", "teacher"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin', 'student', or 'teacher'")

    if user.role == "student" and user.id in valid_student_ids:
        raise HTTPException(status_code=400, detail="Student ID already registered")
    if user.role == "teacher" and user.id in valid_teacher_ids:
        raise HTTPException(status_code=400, detail="Teacher ID already registered")
    if user.role == "admin":
        existing_admin = await admins_collection.find_one({"id": user.id})
        if existing_admin:
            raise HTTPException(status_code=400, detail="Admin ID already registered")

    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    user_dict.pop("password")

    try:
        if user.role == "admin":
            await admins_collection.insert_one(user_dict)
        elif user.role == "student":
            await student_info_collection.insert_one(user_dict)
            valid_student_ids.add(user.id)
        elif user.role == "teacher":
            await teacher_info_collection.insert_one(user_dict)
            valid_teacher_ids.add(user.id)

        return {
            "message": "Registration successful",
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "id": user.id
        }
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email or username already exists")

@app.post("/admin/students")
async def create_student(student: StudentCreate, admin: dict = Depends(get_admin_user)):
    if student.id in valid_student_ids:
        raise HTTPException(status_code=400, detail="Student ID already registered")
    
    hashed_password = get_password_hash(student.password)
    student_dict = student.dict()
    user_dict["hashed_password"] = hashed_password
    student_dict.pop("password")
    
    try:
        await student_info_collection.insert_one(student_dict)
        valid_student_ids.add(student.id)
        return {"message": "Student created successfully", "student_id": student.id}
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email or username already exists")

@app.post("/admin/teachers")
async def create_teacher(teacher: TeacherCreate, admin: dict = Depends(get_admin_user)):
    if teacher.id in valid_teacher_ids:
        raise HTTPException(status_code=400, detail="Teacher ID already registered")
    
    hashed_password = get_password_hash(teacher.password)
    teacher_dict = teacher.dict()
    teacher_dict["hashed_password"] = hashed_password
    teacher_dict.pop("password")
    
    try:
        await teacher_info_collection.insert_one(teacher_dict)
        valid_teacher_ids.add(teacher.id)
        return {"message": "Teacher created successfully", "teacher_id": teacher.id}
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email or ID already exists")

@app.post("/login")
async def login_for_access_token(form_data: LoginForm):
    user = None
    role = form_data.role

    if role == "student":
        user = await student_info_collection.find_one({"id": form_data.id})
    elif role == "teacher":
        user = await teacher_info_collection.find_one({"id": form_data.id})
    elif role == "admin":
        user = await admins_collection.find_one({"id": form_data.id})
    else:
        raise HTTPException(status_code=400, detail="Invalid role")

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect ID, password, or role",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["id"], "role": role}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.get("username", ""),
        "role": role,
        "id": user["id"]
    }

@app.post("/admin/subjects")
async def assign_subject(subject: SubjectCreate, admin: dict = Depends(get_admin_user)):
    teacher = await teacher_info_collection.find_one({"id": subject.teacher_id})
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    
    existing_subject = await subjects_collection.find_one({
        "name": subject.name,
        "teacher_id": subject.teacher_id,
        "class_name": subject.class_name
    })
    if existing_subject:
        raise HTTPException(status_code=400, detail="Subject already exists for this class and teacher")
    
    subject_data = {
        "name": subject.name,
        "teacher_id": subject.teacher_id,
        "class_name": subject.class_name,
        "created_by": admin["id"],
        "created_at": datetime.utcnow()
    }
    try:
        result = await subjects_collection.insert_one(subject_data)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Subject already exists for this class and teacher")
    
    await teacher_info_collection.update_one(
        {"id": subject.teacher_id},
        {
            "$addToSet": {
                "subjects": subject.name,
                "classes": subject.class_name
            }
        }
    )
    
    return {
        "message": "Subject assigned successfully",
        "subject_id": str(result.inserted_id),
        "teacher_id": subject.teacher_id,
        "subject_name": subject.name,
        "class_name": subject.class_name
    }

@app.get("/admin/students")
async def get_students(admin: dict = Depends(get_admin_user)):
    students = await student_info_collection.find(
        {},
        {"_id": 0, "id": 1, "username": 1, "email": 1, "speciality": 1}
    ).to_list(100)
    if not students:
        raise HTTPException(status_code=404, detail="No students found")
    return {"students": students}

@app.get("/subjects")
async def get_subjects():
    subjects = await subjects_collection.find().to_list(100)
    for subject in subjects:
        subject["_id"] = str(subject["_id"])
    return subjects

@app.post("/events", response_model=EventResponse)
async def create_event(event: EventCreate, admin: dict = Depends(get_admin_user)):
    try:
        subject = await subjects_collection.find_one({"_id": ObjectId(event.subject_id)})
    except bson.errors.InvalidId:
        raise HTTPException(status_code=400, detail="Invalid subject_id: must be a 24-character hex string")
    
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    if event.class_name != subject["class_name"] or event.teacher_id != subject["teacher_id"]:
        raise HTTPException(status_code=400, detail="Subject does not match class or teacher")

    if event.teacher_id not in valid_teacher_ids:
        raise HTTPException(status_code=404, detail="Teacher not found")

    existing_events = await events_collection.find({
        "teacher_id": event.teacher_id,
        "start_time": {"$lt": event.end_time},
        "end_time": {"$gt": event.start_time}
    }).to_list(None)
    if existing_events:
        raise HTTPException(status_code=400, detail="Teacher has a conflicting schedule")

    event_data = event.dict()
    event_data["created_by"] = admin["id"]
    event_data["created_at"] = datetime.utcnow()

    if event.recurrence == "weekly" and event.recurrence_end:
        duration = event.end_time - event.start_time
        events_to_insert = []
        for dt in rrule(WEEKLY, dtstart=event.start_time, until=event.recurrence_end):
            new_event = event_data.copy()
            new_event["start_time"] = dt
            new_event["end_time"] = dt + duration
            events_to_insert.append(new_event)
        result = await events_collection.insert_many(events_to_insert)
        return {"message": "Recurring events created", "event_ids": [str(id) for id in result.inserted_ids]}
    
    result = await events_collection.insert_one(event_data)
    return {"message": "Event created", "event_ids": [str(result.inserted_id)]}

@app.get("/debug/teacher-ids")
async def debug_teacher_ids():
    return {"valid_teacher_ids": list(valid_teacher_ids)}

@app.get("/events")
async def get_events(start_date: datetime, end_date: datetime, user_id: str, role: str):
    if role == "teacher":
        if user_id not in valid_teacher_ids:
            raise HTTPException(status_code=404, detail="Teacher not found")
        query = {
            "teacher_id": user_id,
            "start_time": {"$gte": start_date, "$lte": end_date}
        }
    elif role == "student":
        if user_id not in valid_student_ids:
            raise HTTPException(status_code=404, detail="Student not found")
        student = await student_info_collection.find_one({"id": user_id})
        if not student:
            raise HTTPException(status_code=404, detail="Student not found")
        query = {
            "class_name": student["speciality"],
            "start_time": {"$gte": start_date, "$lte": end_date}
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid role")

    events = await events_collection.find(query).to_list(100)
    for event in events:
        event["_id"] = str(event["_id"])
    return events

@app.post("/attendance")
async def mark_attendance(attendance: AttendanceCreate):
    try:
        subject = await subjects_collection.find_one({"_id": ObjectId(attendance.subject_id)})
        event = await events_collection.find_one({"_id": ObjectId(attendance.event_id)})
    except bson.errors.InvalidId:
        raise HTTPException(status_code=400, detail="Invalid subject_id or event_id: must be a 24-character hex string")
    
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if attendance.student_id not in valid_student_ids:
        raise HTTPException(status_code=404, detail="Student not found")
    
    student = await student_info_collection.find_one({"id": attendance.student_id})
    if student["speciality"] != event["class_name"]:
        raise HTTPException(status_code=400, detail="Student not enrolled in this class")
    
    event_date = event["start_time"].date()
    attendance_date = attendance.date.date()
    if event_date != attendance_date:
        raise HTTPException(status_code=400, detail="Attendance date does not match event date")
    
    event_start = event["start_time"].time()
    event_end = event["end_time"].time()
    if not (event_start <= attendance.date.time() <= event_end):
        raise HTTPException(status_code=400, detail="Attendance time outside event time slot")
    
    if subject["_id"] != ObjectId(attendance.subject_id):
        raise HTTPException(status_code=400, detail="Subject does not match event")
    
    try:
        await attendance_collection.insert_one(attendance.dict())
        return {"message": "Attendance marked successfully"}
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Attendance already marked for this student, subject, event, and date")

@app.get("/attendance")
async def get_attendance(student_id: str, subject_id: str):
    try:
        subject = await subjects_collection.find_one({"_id": ObjectId(subject_id)})
    except bson.errors.InvalidId:
        raise HTTPException(status_code=400, detail="Invalid subject_id: must be a 24-character hex string")
    
    if not subject:
        raise HTTPException(status_code=404, detail="Subject not found")
    if student_id not in valid_student_ids:
        raise HTTPException(status_code=404, detail="Student not found")
    
    student = await student_info_collection.find_one({"id": student_id})
    if student["speciality"] != subject["class_name"]:
        raise HTTPException(status_code=400, detail="Student not enrolled in this class")
    
    attendance_records = await attendance_collection.find({
        "student_id": student_id,
        "subject_id": subject_id
    }).to_list(100)
    for record in attendance_records:
        record["_id"] = str(record["_id"])
    return attendance_records

@app.post("/admin/calendar")
async def create_calendar(entry: CalendarEntry, admin: dict = Depends(get_admin_user)):
    if entry.day_of_week not in VALID_DAYS:
        raise HTTPException(status_code=400, detail="Invalid day_of_week. Must be Monday to Friday")

    try:
        start_time = parse(entry.start_time).time()
        end_time = parse(entry.end_time).time()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid time format. Use HH:MM (e.g., '08:00')")

    if start_time >= end_time:
        raise HTTPException(status_code=400, detail="start_time must be before end_time")

    for schedule in entry.schedules:
        if schedule.teacher_id not in valid_teacher_ids:
            raise HTTPException(status_code=404, detail=f"Teacher ID {schedule.teacher_id} not found")
        
        teacher = await teacher_info_collection.find_one({"id": schedule.teacher_id})
        if not teacher:
            raise HTTPException(status_code=404, detail=f"Teacher {schedule.teacher_id} not found")
        if schedule.subject_name not in teacher["subjects"]:
            raise HTTPException(status_code=400, detail=f"Subject {schedule.subject_name} not assigned to teacher")
        if schedule.class_name not in teacher["classes"]:
            raise HTTPException(status_code=400, detail=f"Class {schedule.class_name} not assigned to teacher")

        subject = await subjects_collection.find_one({
            "name": schedule.subject_name,
            "teacher_id": schedule.teacher_id,
            "class_name": schedule.class_name
        })
        if not subject:
            raise HTTPException(
                status_code=404,
                detail=f"Subject {schedule.subject_name} for class {schedule.class_name} not found"
            )

    calendar_entry = {
        "day_of_week": entry.day_of_week,
        "start_time": entry.start_time,
        "end_time": entry.end_time,
        "schedules": [s.dict() for s in entry.schedules],
        "created_by": admin["id"],
        "created_at": datetime.utcnow()
    }
    try:
        await calendar_collection.insert_one(calendar_entry)
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(
            status_code=400,
            detail="Schedule already exists for this day, time, and class"
        )

    if entry.recurrence_end:
        event_ids = []
        utc = pytz.UTC
        start_date = datetime.now(utc).replace(
            hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0
        )
        days_ahead = (VALID_DAYS.index(entry.day_of_week) - start_date.weekday()) % 7
        start_date = start_date + timedelta(days=days_ahead)

        if entry.recurrence_end.tzinfo is None:
            recurrence_end = utc.localize(entry.recurrence_end)
        else:
            recurrence_end = entry.recurrence_end.astimezone(utc)

        for dt in rrule(WEEKLY, dtstart=start_date, until=recurrence_end):
            for schedule in entry.schedules:
                subject = await subjects_collection.find_one({
                    "name": schedule.subject_name,
                    "teacher_id": schedule.teacher_id,
                    "class_name": schedule.class_name
                })
                event_data = {
                    "title": f"{schedule.subject_name} for {schedule.class_name}",
                    "event_type": "class",
                    "subject_id": str(subject["_id"]),
                    "teacher_id": schedule.teacher_id,
                    "class_name": schedule.class_name,
                    "start_time": dt,
                    "end_time": dt + timedelta(hours=(end_time.hour - start_time.hour)),
                    "created_by": admin["id"],
                    "created_at": datetime.utcnow()
                }
                existing_events = await events_collection.find({
                    "teacher_id": schedule.teacher_id,
                    "start_time": {"$lt": event_data["end_time"]},
                    "end_time": {"$gt": event_data["start_time"]}
                }).to_list(None)
                if existing_events:
                    continue
                result = await events_collection.insert_one(event_data)
                event_ids.append(str(result.inserted_id))

        return {"message": "Calendar created with recurring events", "event_ids": event_ids}

    return {"message": "Calendar created", "event_ids": []}

@app.get("/admin/subjects", response_model=List[SubjectResponse])
async def get_all_subjects(admin: dict = Depends(get_admin_user)):
    subjects = await subjects_collection.find().to_list(None)
    if not subjects:
        raise HTTPException(status_code=404, detail="No subjects found")
    
    subject_responses = []
    for subject in subjects:
        teacher = await teacher_info_collection.find_one({"id": subject["teacher_id"]})
        teacher_name = teacher["name"] if teacher else "Unknown"
        
        subject_responses.append({
            "subject_id": str(subject["_id"]),
            "name": subject["name"],
            "teacher_id": subject["teacher_id"],
            "teacher_name": teacher_name,
            "class_name": subject["class_name"],
            "created_by": subject["created_by"],
            "created_at": subject["created_at"]
        })
    
    return subject_responses

@app.get("/admin/calendar", response_model=List[CalendarEntryResponse])
async def get_admin_calendar(admin: dict = Depends(get_admin_user)):
    calendar_entries = await calendar_collection.find().to_list(None)
    
    if not calendar_entries:
        raise HTTPException(status_code=404, detail="No calendar entries found")
    
    calendar_response = []
    for entry in calendar_entries:
        schedules = []
        for schedule in entry["schedules"]:
            teacher = await teacher_info_collection.find_one({"id": schedule["teacher_id"]})
            teacher_name = teacher["name"] if teacher else "Unknown"
            
            subject = await subjects_collection.find_one({
                "name": schedule["subject_name"],
                "teacher_id": schedule["teacher_id"],
                "class_name": schedule["class_name"]
            })
            subject_id = str(subject["_id"]) if subject else None
            
            schedules.append({
                "class_name": schedule["class_name"],
                "subject_name": schedule["subject_name"],
                "subject_id": subject_id,
                "teacher_id": schedule["teacher_id"],
                "teacher_name": teacher_name
            })
        
        calendar_response.append({
            "entry_id": str(entry["_id"]),
            "day_of_week": entry["day_of_week"],
            "start_time": entry["start_time"],
            "end_time": entry["end_time"],
            "schedules": schedules,
            "recurrence_end": entry.get("recurrence_end"),
            "created_by": entry["created_by"],
            "created_at": entry["created_at"]
        })
    
    return calendar_response

@app.delete("/admin/calendar/{entry_id}")
async def delete_calendar_entry(entry_id: str, admin: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(entry_id):
            raise HTTPException(status_code=400, detail="Invalid calendar entry ID")
        
        result = await calendar_collection.delete_one({"_id": ObjectId(entry_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Calendar entry not found")
        
        return {"message": "Calendar entry deleted successfully"}
    
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/teachers/{teacher_id}", response_model=dict)
async def get_teacher(teacher_id: str, user: dict = Depends(get_teacher_or_admin)):
    teacher = await teacher_info_collection.find_one({"id": teacher_id})
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    if user["role"] == "teacher" and user["id"] != teacher_id:
        raise HTTPException(status_code=403, detail="Cannot access other teacher's details")
    teacher.pop("hashed_password", None)
    teacher["_id"] = str(teacher["_id"])
    return teacher

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)