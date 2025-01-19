from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
import random
from datetime import datetime
from typing import List, Dict

app = FastAPI()

# Настройка CORS middleware для разрешения кросс-доменных запросов
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Настройки Keycloak
KEYCLOAK_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----""" 
KEYCLOAK_ALGORITHM = "RS256"
KEYCLOAK_ISSUER = "http://localhost:8080/realms/reports-realm"

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token,
            KEYCLOAK_PUBLIC_KEY,
            algorithms=[KEYCLOAK_ALGORITHM],
            issuer=KEYCLOAK_ISSUER
        )
        
        # Проверяем наличие роли prothetic_user
        realm_access = payload.get("realm_access", {})
        roles = realm_access.get("roles", [])
        
        if "prothetic_user" not in roles:
            raise HTTPException(
                status_code=403,
                detail="У пользователя отсутствует необходимая роль"
            )
            
        return payload
        
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Недействительный токен аутентификации"
        )

def generate_random_report_data() -> List[Dict]:
    """
    Генерирую случайные данные для отчета
    """
    products = ["Продукт А", "Продукт Б", "Продукт В", "Продукт Г"]
    report_data = []
    
    for _ in range(random.randint(5, 10)):
        report_data.append({
            "product": random.choice(products),
            "quantity": random.randint(10, 1000),
            "revenue": round(random.uniform(1000, 10000), 2),
            "date": datetime.now().isoformat()
        })
    
    return report_data

@app.get("/reports")
async def get_reports(token_data: dict = Depends(verify_token)):
    """
    Получение данных отчета.
    Доступно только пользователям с ролью prothetic_user.
    """
    return {
        "status": "успешно",
        "data": generate_random_report_data()
    }

@app.get("/health")
async def health_check():
    """
    Эндпоинт проверки работоспособности сервиса.
    Не требует аутентификации.
    """
    return {"status": "работает"}
