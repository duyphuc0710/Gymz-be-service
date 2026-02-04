# Gymz-backend-service
Gymz backend-service with SpringBoot

## Technologies Used

- **Java 17**
- **Spring Boot 3.5.4**
- **Spring Security**
- **Spring Data JPA**
- **MySQL**
- **Maven**
- **BCrypt** 

## Project Structure

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

## Installation and Running the Application

### System Requirements

- **Java 17** 
- **Maven 3.6+**
- **Docker** 

# Project Guide

## Step 1: Start ELK Stack with Docker Compose

Start the application using:

```powershell
docker-compose up -d
```

## Step 2: Run the Spring Boot Application

Start the application using:

```powershell
./mvnw spring-boot:run
```

Or, if Maven is already installed on your system:

```powershell
mvn spring-boot:run
```

