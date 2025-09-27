package com.backend_service.gymz.user.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptExample {
    public static void main(String[] args) {
        // Khởi tạo BCryptPasswordEncoder
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        // Tạo mật khẩu bcrypt
        String password = "123456";
        String hashedPassword = encoder.encode(password);

        // In ra mật khẩu đã băm
        System.out.println("Hashed password: " + hashedPassword);
    }
}

