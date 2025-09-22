from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import requests

# -------------------- Configs/JWT --------------------
SECRET_KEY = "ABFD-EFG-HIJ"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -------------------- DB Setup -----------------------
DATABASE_URL = "sqlite:///./usuarios.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------- Modelos ORM --------------------
class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String, unique=True, index=True, nullable=False)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# -------------------- Schemas Pydantic --------------------
class UsuarioCreate(BaseModel):
    usuario: str
    nome: str
    email: EmailStr
    senha: str

class UsuarioUpdate(BaseModel):
    nome: Optional[str] = None
    email: Optional[EmailStr] = None
    senha: Optional[str] = None

class UsuarioOut(BaseModel):
    id: int
    usuario: str
    nome: str
    email: EmailStr
    class Config:
        from_attributes = True  # pydantic v2

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    sub: Optional[str] = None  # username (usuario)

# -------------------- Segurança (hash/verify + JWT) --------------------
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_username(db: Session, username: str) -> Optional[UsuarioDB]:
    return db.query(UsuarioDB).filter(UsuarioDB.usuario == username).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[UsuarioDB]:
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UsuarioDB:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exc
        token_data = TokenData(sub=username)
    except JWTError:
        raise credentials_exc
    user = get_user_by_username(db, token_data.sub)
    if user is None:
        raise credentials_exc
    return user

# -------------------- FastAPI App --------------------
app = FastAPI(title="API de Usuários")

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "null"],  # Ou ["*"] para desenvolvimento
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rota inicial GET
@app.get("/")
def read_root():
    return {"message": "API de Login esta rodando...."}

# --------- Auth: obter token (login) ----------
@app.post("/token", response_model=Token, summary="Login e obtenção de token JWT")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm usa campos: username, password
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário ou senha inválidos")
    access_token = create_access_token(data={"sub": user.usuario})
    return {"access_token": access_token, "token_type": "bearer"}

# --------- Cadastro (público) ----------
@app.post("/usuarios/", response_model=UsuarioOut, status_code=201, summary="Criar novo usuário")
def criar_usuario(payload: UsuarioCreate, db: Session = Depends(get_db)):
    if db.query(UsuarioDB).filter(UsuarioDB.usuario == payload.usuario).first():
        raise HTTPException(status_code=400, detail="Usuário já existe")
    if db.query(UsuarioDB).filter(UsuarioDB.email == payload.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    user = UsuarioDB(
        usuario=payload.usuario,
        nome=payload.nome,
        email=payload.email,
        hashed_password=get_password_hash(payload.senha),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# --------- Rotas protegidas ----------
@app.get("/usuarios/", response_model=List[UsuarioOut], summary="Listar usuários (protegido)")
def listar_usuarios(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(UsuarioDB).all()

@app.get("/usuarios/me", response_model=UsuarioOut, summary="Meu perfil (protegido)")
def meu_perfil(current_user: UsuarioDB = Depends(get_current_user)):
    return current_user

@app.get("/usuarios/{user_id}", response_model=UsuarioOut, summary="Buscar usuário por ID (protegido)")
def buscar_usuario(user_id: int, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return user

@app.put("/usuarios/{user_id}", response_model=UsuarioOut, summary="Atualizar usuário (protegido)")
def atualizar_usuario(user_id: int, payload: UsuarioUpdate, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if payload.nome is not None:
        user.nome = payload.nome
    if payload.email is not None:
        # checar duplicidade de email
        exists = db.query(UsuarioDB).filter(UsuarioDB.email == payload.email, UsuarioDB.id != user_id).first()
        if exists:
            raise HTTPException(status_code=400, detail="E-mail já cadastrado por outro usuário")
        user.email = payload.email
    if payload.senha is not None:
        user.hashed_password = get_password_hash(payload.senha)

    db.commit()
    db.refresh(user)
    return user

@app.delete("/usuarios/{user_id}", summary="Deletar usuário (protegido)")
def deletar_usuario(user_id: int, current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UsuarioDB).filter(UsuarioDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    db.delete(user)
    db.commit()
    return {"message": "Usuário deletado com sucesso"}

# Endpoint para validar token
@app.get("/valida-token")
async def validate_token(current_user: UsuarioDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"valid": True, "username": current_user}

# Modelo de resposta
class PrevisaoTempoOut(BaseModel):
    cidade: str
    pais: str
    previsao: Optional[dict] = None
    mensagem: Optional[str] = None

# Modelo para dados de localização
class Localizacao(BaseModel):
    ip: Optional[str] = None
    cidade: str
    regiao: str
    pais: str
    lat: float
    lon: float

# Função para obter localização por IP
def get_location_by_ip(ip=None):
    try:
        url = f"http://ipapi.co/{ip}/json/" if ip else "http://ipapi.co/json/"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return Localizacao(
                ip=data.get('ip'),
                cidade=data.get('city'),
                regiao=data.get('region'),
                pais=data.get('country_name'),
                lat=data.get('latitude'),
                lon=data.get('longitude')
            )
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erro ao obter localização: {e}")
        return None

# Função para obter previsão do tempo
def get_weather(lat, lon):
    try:
        # Corrigido: removidas as aspas extras around {lat}
        url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&hourly=temperature_2m&current_weather=true"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'temperatura_atual': data.get('current_weather', {}).get('temperature'),
                'codigo_tempo': data.get('current_weather', {}).get('weathercode'),
                'hora': data.get('current_weather', {}).get('time'),
                'hourly': {
                    'time': data.get('hourly', {}).get('time'),
                    'temperature_2m': data.get('hourly', {}).get('temperature_2m')
                }
            }
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erro ao obter previsão do tempo: {e}")
        return None

# Endpoint para previsão do tempo
@app.get("/previsao-tempo", response_model=PrevisaoTempoOut, status_code=200, summary="Previsão do Tempo")
async def previsao_tempo():
    # Obtém a localização pelo IP
    location = get_location_by_ip()
    print('Localização obtida:', location)
    
    if not location:
        raise HTTPException(status_code=500, detail="Não foi possível obter a localização")
    
    # Obtém a previsão do tempo
    previsao = get_weather(location.lat, location.lon)
    print('Previsão obtida:', previsao)
    
    if not previsao:
        return PrevisaoTempoOut(
            cidade=location.cidade,
            pais=location.pais,
            mensagem="Não foi possível obter a previsão do tempo"
        )
    
    return PrevisaoTempoOut(
        cidade=location.cidade,
        pais=location.pais,
        previsao=previsao
    )