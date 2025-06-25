# Centralized Authentication Server (Spring Boot + OAuth2 + Thymeleaf)

This project is a centralized **Authentication Server** built using **Spring Boot**, **Spring Security OAuth2 Authorization Server**, and **Thymeleaf** for UI rendering. It is designed to authenticate users across multiple client applications and supports user self-registration.

---

## Features

- OAuth2 Authorization Server (with PKCE support)
- Centralized login for multiple client applications
- User self-registration via UI
- Secure form-based login (Thymeleaf)
- Token issuance via standard OAuth2 flows
- Session-based login and token-based API access
- Configurable client registration (from DB or in-memory)

---

## Tech Stack

- Spring Boot `3.x`
- Spring Security + Spring Authorization Server `1.4.0`
- Thymeleaf (for login/signup pages)
- MySQL (for user storage)
- Spring Data JPA

---

## How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/auth-server.git
cd auth-server
2. Configure Database (Optional)
Set your DB config in application.properties:

properties
Copy
Edit
spring.datasource.url=jdbc:h2:mem:authdb
spring.datasource.driver-class-name=org.h2.Driver
spring.jpa.hibernate.ddl-auto=update
You can switch to MySQL/PostgreSQL as needed.

3. Build and Run
bash
Copy
Edit
./mvnw spring-boot:run
4. Access the App
UI: http://localhost:8080

Login Page: /login

Registration Page: /signup

Token Endpoint: /oauth2/token

Authorization Endpoint: /oauth2/authorize

👤 User Management
Users can register at /signup

Passwords are securely stored using BCryptPasswordEncoder

Admins can be created manually or via DB scripts

🧩 Client Registration
Clients can be:

Configured in-memory via RegisteredClientRepository

Each client can specify:

client_id, client_secret

Authorized redirect URIs

Scopes and grant types (authorization_code, refresh_token, etc.)

Endpoints Overview
Endpoint	Description
/login	Login form
/signup	New user registration
/oauth2/authorize	OAuth2 Authorization endpoint
/oauth2/token	Token issuance endpoint
/logout	End session
/userinfo (optional)	OIDC user info (if implemented)

📦 Dependencies
xml
Copy
Edit
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>1.4.0</version>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

 Testing
You can test the flow using:

Postman (OAuth2 Authorization Code with PKCE)

Browser login redirects with client apps

UI-based form login and registration

