from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
import httpx
import random
from datetime import datetime
from typing import List, Dict
import os

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
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = "reports-realm"

async def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    try:
        token = credentials.credentials
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail="Не удалось получить ключ для проверки токена"
                )
            
            keys = response.json()
            # Берем первый ключ из набора ключей
            key = keys['keys'][0]
            
            # Проверяем JWT токен
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience="reports-frontend"  # Важно: указываем правильный client_id
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
            
    except JWTError as e:
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
