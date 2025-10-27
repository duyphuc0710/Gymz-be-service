# Gymz-backend-service
Gymz backend-service with SpringBoot

## Công nghệ sử dụng

- **Java 17**
- **Spring Boot 3.5.4**
- **Spring Security** (OAuth2 + Database Auth)
- **Spring Data JPA**
- **MySQL**
- **Maven**
- **Keycloak** (OAuth2/OIDC Server)
- **BCrypt** (mã hóa mật khẩu)


## Cài đặt và chạy ứng dụng

### Yêu cầu hệ thống

- **Java 17** hoặc cao hơn
- **Maven 3.6+**
- **Docker** và **Docker Compose**

# Hướng dẫn sử dụng project

## Bước 1: Khởi động ELK bằng Docker Compose

Chạy lệnh sau trong thư mục gốc của project để dựng ELK stack:

```powershell
docker-compose up -d
```

## Bước 2: Chạy project Spring Boot

Chạy lệnh sau để khởi động ứng dụng:

```powershell
./mvnw spring-boot:run
```

Hoặc nếu đã cài đặt Maven trên máy:

```powershell
mvn


## Spring Security - Authentication Flows

### � Tổng Quan: 3 Security Filter Chains

```
                           ┌─────────────────────────────────────┐
                           │    HTTP Request đến Backend         │
                           └──────────────┬──────────────────────┘
                                          │
                                          ▼
                           ┌──────────────────────────────┐
                           │   Spring Security Router     │
                           │   (Check URL Pattern)        │
                           └──────────────┬───────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
         ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
         │  Filter Chain 1  │  │  Filter Chain 2  │  │  Filter Chain 3  │
         │   @Order(1)      │  │   @Order(2)      │  │   @Order(3)      │
         ├──────────────────┤  ├──────────────────┤  ├──────────────────┤
         │  Pattern:        │  │  Pattern:        │  │  Pattern:        │
         │  /api/**         │  │  /oauth2/**      │  │  /** (catch-all) │
         │                  │  │  /login/oauth2/**│  │                  │
         ├──────────────────┤  ├──────────────────┤  ├──────────────────┤
         │  Auth Type:      │  │  Auth Type:      │  │  Auth Type:      │
         │  OAuth2 Resource │  │  OAuth2 Client   │  │  Database Auth   │
         │  Server          │  │  (Login Flow)    │  │  + Custom JWT    │
         ├──────────────────┤  ├──────────────────┤  ├──────────────────┤
         │  Token:          │  │  Session:        │  │  Token:          │
         │  Keycloak JWT    │  │  Stateful        │  │  Custom JWT      │
         │  (RS256)         │  │  (IF_REQUIRED)   │  │  (HS256)         │
         ├──────────────────┤  ├──────────────────┤  ├──────────────────┤
         │  Validate via:   │  │  Redirect to:    │  │  Validate via:   │
         │  Keycloak JWK    │  │  Keycloak Login  │  │  Secret Key      │
         └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘
                  │                     │                     │
                  └─────────────────────┼─────────────────────┘
                                        │
                                        ▼
                              ┌──────────────────┐
                              │   Process Request │
                              │   & Return Data   │
                              └───────────────────┘
```

**Routing Logic:**
1. Request `/api/users` → Filter Chain 1 (OAuth2 Resource Server)
2. Request `/oauth2/authorization/keycloak` → Filter Chain 2 (OAuth2 Client)
3. Request `/dashboard` → Filter Chain 3 (Database Auth)

---

### Chi Tiết Từng Luồng

#### �🔐 Flow 1: OAuth2 via Keycloak (API endpoints)

```
┌────────┐                  ┌─────────┐                 ┌──────────┐
│ Client │                  │ Backend │                 │ Keycloak │
└───┬────┘                  └────┬────┘                 └────┬─────┘
    │                            │                           │
    │ GET /api/users             │                           │
    │ Bearer <keycloak_token>    │                           │
    │──────────────────────────> │                           │
    │                            │                           │
    │                            │  Validate JWT (RS256)     │
    │                            │ ────────────────────────> │
    │                            │                           │
    │                            │      Token valid          │
    │                            │ <──────────────────────── │
    │                            │                           │
    │      200 OK + Data         │                           │
    │ <──────────────────────────│                           │
    │                            │                           │
```

**Mô tả:**
- Client gọi API với Bearer token từ Keycloak
- Backend validate token với Keycloak (RS256)
- Nếu valid → trả về data

---

#### 🌐 Flow 2: OAuth2 Login (Web)

```
┌──────┐              ┌─────────┐              ┌──────────┐
│ User │              │ Backend │              │ Keycloak │
└──┬───┘              └────┬────┘              └────┬─────┘
   │                       │                        │
   │ Click "Login"         │                        │
   │ ────────────────────> │                        │
   │                       │                        │
   │                       │  302 Redirect          │
   │ <──────────────────── │                        │
   │                       │                        │
   │                  Login Page                    │
   │ ─────────────────────────────────────────────> │
   │                       │                        │
   │              Enter username/password           │
   │ ─────────────────────────────────────────────> │
   │                       │                        │
   │                       │   Return token & code  │
   │                       │ <───────────────────── │
   │                       │                        │
   │  Redirect to /dashboard                        │
   │ <──────────────────── │                        │
   │                       │                        │
```

**Mô tả:**
- User click login → redirect đến Keycloak
- User nhập credentials trên Keycloak
- Keycloak redirect về Backend với token
- Backend redirect user đến /dashboard

---

#### 🗄️ Flow 3: Database Login (Traditional)

```
┌────────┐                  ┌─────────┐                 ┌──────────┐
│ Client │                  │ Backend │                 │ Database │
└───┬────┘                  └────┬────┘                 └────┬─────┘
    │                            │                           │
    │ POST /api/auth/login       │                           │
    │ {username, password}       │                           │
    │──────────────────────────> │                           │
    │                            │                           │
    │                            │  Query user & verify      │
    │                            │ ────────────────────────> │
    │                            │                           │
    │                            │     User found            │
    │                            │ <──────────────────────── │
    │                            │                           │
    │                            │  [Generate JWT HS256]     │
    │                            │                           │
    │   200 OK + {token}         │                           │
    │ <──────────────────────────│                           │
    │                            │                           │
    │                            │                           │
    │ ═══════════════════════════════════════════════════════│
    │      Subsequent Requests                               │
    │ ═══════════════════════════════════════════════════════│
    │                            │                           │
    │ GET /dashboard             │                           │
    │ Bearer <custom_jwt>        │                           │
    │──────────────────────────> │                           │
    │                            │                           │
    │                            │  [Validate JWT locally]   │
    │                            │                           │
    │      200 OK + Data         │                           │
    │ <──────────────────────────│                           │
    │                            │                           │
```

**Mô tả:**
- Client POST username/password → Backend
- Backend check database & generate custom JWT (HS256)
- Client lưu token và dùng cho các request sau
- Backend tự validate JWT không cần gọi external service

---

**Filter Priority:** `/api/**` → OAuth2 Client → Database Auth (catch-all)

## Cấu trúc dự án

```
src/main/java/com/vnair/usermanagement/
├── controller/          # REST Controllers
├── service/            # Business Logic Layer
├── repository/         # Data Access Layer
├── model/            # JPA Entities
├── dto/               # Data Transfer Objects
├── exception/         # Exception Handling
└── UserManagementApiApplication.java
```

## Cài đặt và chạy ứng dụng

### Yêu cầu hệ thống

- **Java 17** hoặc cao hơn
- **Maven 3.6+**
- **Docker** và **Docker Compose**

# Hướng dẫn sử dụng project

## Bước 1: Khởi động ELK bằng Docker Compose

Chạy lệnh sau trong thư mục gốc của project để dựng ELK stack:

```powershell
docker-compose up -d
```

## Bước 2: Chạy project Spring Boot

Chạy lệnh sau để khởi động ứng dụng:

```powershell
./mvnw spring-boot:run
```

Hoặc nếu đã cài đặt Maven trên máy:

```powershell
mvn spring-boot:run
```

