"""
Database Schemas for E-commerce App

Each Pydantic model correlates to a MongoDB collection. The collection name is the lowercase of the class name.
- User -> "user"
- Product -> "product"
- Order -> "order"

These models are used for request/response validation and for documenting schema via /schema endpoint (auto-read by the platform).
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_admin: bool = Field(False, description="Is admin user")


class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: str = Field(..., description="Product description")
    price: float = Field(..., ge=0, description="Price in USD")
    category: Literal["Mobiles", "Laptops", "Accessories", "Fashion"] = Field(
        ..., description="Product category"
    )
    brand: str = Field(..., description="Brand name")
    rating: float = Field(4.2, ge=0, le=5, description="Average rating")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    stock: int = Field(10, ge=0, description="Units in stock")


class OrderItem(BaseModel):
    product_id: str
    quantity: int = Field(1, ge=1)
    price_at_purchase: float


class Order(BaseModel):
    user_id: Optional[str] = Field(None, description="User placing the order")
    items: List[OrderItem]
    name: str
    address: str
    phone: str
    payment_method: Literal["COD", "Card", "UPI"] = "COD"
    total: float


# Lightweight request models
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
