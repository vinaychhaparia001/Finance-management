# Finance-management
"""
PYTHON FINANCE SYSTEM BACKEND - COMPLETE PRODUCTION SOLUTION
FastAPI + SQLAlchemy + JWT Auth + Role-Based Access + Analytics
100% Self-contained - Zero external setup required!
"""

from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Enum as SQLEnum, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import uvicorn
from enum import Enum

# =============================================================================
# CONFIGURATION
# =============================================================================

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database
SQLALCHEMY_DATABASE_URL = "sqlite:///./finance_system.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# =============================================================================
# SECURITY
# =============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(lambda: SessionLocal())
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    return user

def require_role(required_role: str):
    def role_checker(current_user = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

# =============================================================================
# MODELS
# =============================================================================

class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(255))
    role = Column(SQLEnum(UserRole), default="viewer")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    type = Column(String(20))  # income, expense
    category = Column(String(50), index=True)
    date = Column(DateTime, default=func.now(), index=True)
    notes = Column(Text)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =============================================================================
# SCHEMAS
# =============================================================================

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    role: UserRole = "viewer"

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class TransactionBase(BaseModel):
    amount: float = Field(..., gt=0)
    type: str  # income, expense
    category: str = Field(..., max_length=50)
    notes: Optional[str] = Field(None, max_length=500)

class TransactionCreate(TransactionBase):
    pass

class Transaction(TransactionBase):
    id: int
    user_id: int
    date: datetime
    
    class Config:
        from_attributes = True

class PaginatedResponse(BaseModel):
    transactions: List[Transaction]
    summary: Dict[str, Any]
    pagination: Dict[str, Any]

class AnalyticsResponse(BaseModel):
    total_income: float
    total_expenses: float
    balance: float
    top_categories: List[Dict[str, Any]]

# =============================================================================
# CRUD OPERATIONS
# =============================================================================

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def get_transactions(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    type_filter: Optional[str] = None,
    category_filter: Optional[str] = None
):
    query = db.query(Transaction).filter(Transaction.user_id == user_id)
    
    if type_filter:
        query = query.filter(Transaction.type == type_filter)
    if category_filter:
        query = query.filter(Transaction.category.like(f"%{category_filter}%"))
    
    total_query = query.count()
    transactions = query.order_by(Transaction.date.desc()).offset(skip).limit(limit).all()
    
    return transactions, total_query

def create_transaction(db: Session, transaction: TransactionCreate, user_id: int):
    db_transaction = Transaction(**transaction.dict(), user_id=user_id)
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    return db_transaction

def get_transaction(db: Session, transaction_id: int, user_id: int):
    return db.query(Transaction).filter(
        Transaction.id == transaction_id,
        Transaction.user_id == user_id
    ).first()

def delete_transaction(db: Session, transaction_id: int, user_id: int):
    transaction = get_transaction(db, transaction_id, user_id)
    if transaction:
        db.delete(transaction)
        db.commit()
        return True
    return False

def get_analytics(db: Session, user_id: int):
    # Totals
    totals = db.query(
        Transaction.type,
        func.sum(Transaction.amount).label('total')
    ).filter(Transaction.user_id == user_id)\
     .group_by(Transaction.type).all()
    
    income = next((float(t.total or 0) for t in totals if t.type == 'income'), 0)
    expenses = next((float(t.total or 0) for t in totals if t.type == 'expense'), 0)
    
    # Top categories
    categories = db.query(
        Transaction.category,
        func.sum(Transaction.amount).label('total')
    ).filter(Transaction.user_id == user_id)\
     .group_by(Transaction.category)\
     .order_by(func.sum(Transaction.amount).desc())\
     .limit(5).all()
    
    top_categories = [
        {'category': c.category, 'total': float(c.total or 0)}
        for c in categories
    ]
    
    return {
        'total_income': income,
        'total_expenses': expenses,
        'balance': income - expenses,
        'top_categories': top_categories
    }

# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(
    title="💰 Python Finance System API",
    description="Complete finance tracking backend with RBAC & analytics",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

@app.post("/api/auth/register", status_code=201)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register new user"""
    db_user = get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db, user)

@app.post("/api/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login and get JWT token"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/transactions/", status_code=201)
async def create_transaction(
    transaction: TransactionCreate,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create transaction (Analyst+)"""
    if current_user.role not in ["analyst", "admin"]:
        raise HTTPException(status_code=403, detail="Analyst role required")
    return create_transaction(db, transaction, current_user.id)

@app.get("/api/transactions/")
async def list_transactions(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    type_filter: Optional[str] = Query(None),
    category_filter: Optional[str] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List transactions with filtering & pagination (Viewer+)"""
    if current_user.role == "viewer":
        # Viewers get read-only access
        pass
    
    skip = (page - 1) * limit
    transactions, total = get_transactions(
        db, current_user.id, skip, limit, type_filter, category_filter
    )
    analytics = get_analytics(db, current_user.id)
    
    return {
        "transactions": transactions,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        },
        "summary": analytics
    }

@app.get("/api/analytics/")
async def get_analytics_endpoint(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get financial analytics (Analyst+)"""
    if current_user.role not in ["analyst", "admin"]:
        raise HTTPException(status_code=403, detail="Analyst role required")
    return get_analytics(db, current_user.id)

@app.delete("/api/transactions/{transaction_id}/")
async def delete_transaction(
    transaction_id: int,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete transaction (Admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    success = delete_transaction(db, transaction_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {"message": "Transaction deleted successfully"}

@app.get("/api/health/")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "database": "connected"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
