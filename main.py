import os
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import User, Product, Order, SignupRequest, LoginRequest

JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALGO = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TokenResponse(BaseModel):
    token: str
    name: str
    email: str
    is_admin: bool


def create_token(user_doc: dict) -> str:
    payload = {
        "sub": str(user_doc.get("_id")),
        "email": user_doc["email"],
        "name": user_doc["name"],
        "is_admin": user_doc.get("is_admin", False),
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization:
        return None
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            return None
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        user = db["user"].find_one({"email": payload["email"]})
        return user
    except Exception:
        return None


@app.get("/")
def root():
    return {"status": "ok", "service": "ecommerce-backend"}


@app.get("/schema")
def schema_overview():
    # For platform inspector
    return {
        "collections": ["user", "product", "order"],
    }


# Auth Endpoints
@app.post("/api/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(payload.password.encode(), salt).decode()
    user = User(name=payload.name, email=payload.email, password_hash=password_hash, is_admin=False)
    user_id = create_document("user", user)
    user_doc = db["user"].find_one({"_id": db["user"].find_one({"_id": db["user"].find_one({"email": payload.email})["_id"]})["_id"]})
    # Simpler reload
    user_doc = db["user"].find_one({"email": payload.email})
    token = create_token(user_doc)
    return TokenResponse(token=token, name=user_doc["name"], email=user_doc["email"], is_admin=user_doc.get("is_admin", False))


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(payload.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return TokenResponse(token=token, name=user["name"], email=user["email"], is_admin=user.get("is_admin", False))


# Product Endpoints
@app.get("/api/products")
def list_products(category: Optional[str] = None, q: Optional[str] = None):
    filt = {}
    if category:
        filt["category"] = category
    if q:
        filt["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"brand": {"$regex": q, "$options": "i"}},
        ]
    products = get_documents("product", filt)
    # convert ObjectId to str
    for p in products:
        p["id"] = str(p.pop("_id"))
    return products


@app.get("/api/products/{product_id}")
def get_product(product_id: str):
    from bson import ObjectId

    doc = db["product"].find_one({"_id": ObjectId(product_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Product not found")
    doc["id"] = str(doc.pop("_id"))
    return doc


class ProductPayload(BaseModel):
    title: str
    description: str
    price: float
    category: str
    brand: str
    rating: float = 4.2
    images: List[str] = []
    stock: int = 10


@app.post("/api/admin/products")
def admin_create_product(payload: ProductPayload, user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    prod = Product(**payload.model_dump())
    pid = create_document("product", prod)
    return {"id": pid}


@app.put("/api/admin/products/{product_id}")
def admin_update_product(product_id: str, payload: ProductPayload, user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    from bson import ObjectId

    doc = db["product"].find_one_and_update(
        {"_id": ObjectId(product_id)},
        {"$set": {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}},
        return_document=True,
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"status": "updated"}


@app.delete("/api/admin/products/{product_id}")
def admin_delete_product(product_id: str, user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    from bson import ObjectId

    res = db["product"].delete_one({"_id": ObjectId(product_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"status": "deleted"}


# Orders
class CheckoutPayload(BaseModel):
    name: str
    address: str
    phone: str
    payment_method: str = "COD"
    items: List[dict]
    total: float


@app.post("/api/orders")
def create_order(payload: CheckoutPayload, user=Depends(get_current_user)):
    order = Order(
        user_id=str(user.get("_id")) if user else None,
        items=[
            {"product_id": it["product_id"], "quantity": it["quantity"], "price_at_purchase": it["price"]}
            for it in payload.items
        ],
        name=payload.name,
        address=payload.address,
        phone=payload.phone,
        payment_method=payload.payment_method, 
        total=payload.total,
    )
    oid = create_document("order", order)
    return {"id": oid, "status": "placed"}


@app.get("/api/admin/stats")
def admin_stats(user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    users = db["user"].count_documents({})
    products = db["product"].count_documents({})
    orders = db["order"].count_documents({})
    return {"users": users, "products": products, "orders": orders}


# Seed demo data if empty
@app.post("/api/admin/seed")
def seed_demo(user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    if db["product"].count_documents({}) > 0:
        return {"status": "already-seeded"}

    demo = [
        {
            "title": "Galaxy S22 Ultra",
            "description": "Flagship Android with stunning camera.",
            "price": 999.0,
            "category": "Mobiles",
            "brand": "Samsung",
            "rating": 4.6,
            "images": [
                "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 25,
        },
        {
            "title": "iPhone 14",
            "description": "Apple A15 Bionic, great cameras.",
            "price": 899.0,
            "category": "Mobiles",
            "brand": "Apple",
            "rating": 4.7,
            "images": [
                "https://images.unsplash.com/photo-1670272504572-9c518d910a3f?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 30,
        },
        {
            "title": "ThinkPad X1 Carbon",
            "description": "Ultralight business laptop.",
            "price": 1299.0,
            "category": "Laptops",
            "brand": "Lenovo",
            "rating": 4.5,
            "images": [
                "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 12,
        },
        {
            "title": "MacBook Air M2",
            "description": "Fast, silent, all‑day battery.",
            "price": 1399.0,
            "category": "Laptops",
            "brand": "Apple",
            "rating": 4.8,
            "images": [
                "https://images.unsplash.com/photo-1515879218367-8466d910aaa4?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 9,
        },
        {
            "title": "Sony WH-1000XM5",
            "description": "Industry-leading noise canceling.",
            "price": 349.0,
            "category": "Accessories",
            "brand": "Sony",
            "rating": 4.7,
            "images": [
                "https://images.unsplash.com/photo-1518441902110-266b0c47b1ab?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 40,
        },
        {
            "title": "Apple Watch Series 8",
            "description": "Fitness and health companion.",
            "price": 399.0,
            "category": "Accessories",
            "brand": "Apple",
            "rating": 4.6,
            "images": [
                "https://images.unsplash.com/photo-1518081461904-9ac3d04b797f?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 50,
        },
        {
            "title": "Nike Air Max",
            "description": "Classic comfort sneakers.",
            "price": 129.0,
            "category": "Fashion",
            "brand": "Nike",
            "rating": 4.4,
            "images": [
                "https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 60,
        },
        {
            "title": "Levi's 511 Jeans",
            "description": "Slim fit denim.",
            "price": 59.0,
            "category": "Fashion",
            "brand": "Levi's",
            "rating": 4.3,
            "images": [
                "https://images.unsplash.com/photo-1515955656352-a1fa3ffcd111?q=80&w=1200&auto=format&fit=crop",
            ],
            "stock": 100,
        },
    ]
    for d in demo:
        create_document("product", Product(**d))
    return {"status": "seeded", "count": len(demo)}


# Simple health
@app.get("/test")
def test_database():
    status = {
        "backend": "running",
        "database": "not-configured",
    }
    try:
        db.list_collection_names()
        status["database"] = "connected"
    except Exception:
        status["database"] = "error"
    return status


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
