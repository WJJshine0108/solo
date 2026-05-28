package com.solo.solo_one.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 认证控制器（前后端分离）
 *
 * 提供登录、注册、刷新 Token 等接口
 * 所有接口都返回 JSON 格式数据
 *
 * @author solo
 * @version 1.0
 */
//@RestController
//@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    // private final JwtUtil jwtUtil;  // TODO: 注入 JWT 工具类
    // private final UserDetailsService userDetailsService;

    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * 用户登录接口
     *
     * 请求示例：
     * POST /api/auth/login
     * Content-Type: application/json
     *
     * {
     *   "username": "admin",
     *   "password": "admin123"
     * }
     *
     * 响应示例：
     * {
     *   "code": 200,
     *   "message": "登录成功",
     *   "data": {
     *     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *     "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *     "expiresIn": 86400,
     *     "user": {
     *       "username": "admin",
     *       "roles": ["ROLE_ADMIN"],
     *       "permissions": ["read", "write", "delete"]
     *     }
     *   }
     * }
     *
     * @param loginRequest 登录请求体
     * @return 包含 Token 的响应
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest loginRequest) {
        try {
            // 1. 验证用户名和密码
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // 2. 获取用户信息
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // 3. 生成 JWT Token（TODO: 使用实际的 JWT 工具类）
            String token = generateMockToken(userDetails);
            String refreshToken = generateMockRefreshToken(userDetails);

            // 4. 构建响应
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("token", token);
            responseData.put("refreshToken", refreshToken);
            responseData.put("expiresIn", 86400);  // 24 小时

            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("username", userDetails.getUsername());
            userInfo.put("roles", userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));
            responseData.put("user", userInfo);

            Map<String, Object> response = new HashMap<>();
            response.put("code", 200);
            response.put("message", "登录成功");
            response.put("data", responseData);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // 认证失败
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 401);
            errorResponse.put("message", "用户名或密码错误");
            errorResponse.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.status(401).body(errorResponse);
        }
    }

    /**
     * 用户注册接口
     *
     * 请求示例：
     * POST /api/auth/register
     * Content-Type: application/json
     *
     * {
     *   "username": "newuser",
     *   "password": "password123",
     *   "email": "user@example.com"
     * }
     *
     * @param registerRequest 注册请求体
     * @return 注册结果
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest registerRequest) {
        // TODO: 实现注册逻辑
        // 1. 验证用户名是否已存在
        // 2. 加密密码
        // 3. 保存到数据库
        // 4. 返回成功消息

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("message", "注册成功");

        return ResponseEntity.ok(response);
    }

    /**
     * 刷新 Token 接口
     *
     * 当 Access Token 过期时，使用 Refresh Token 获取新的 Access Token
     *
     * 请求示例：
     * POST /api/auth/refresh-token
     * Content-Type: application/json
     *
     * {
     *   "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
     * }
     *
     * @param refreshTokenRequest 刷新 Token 请求
     * @return 新的 Token
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        // TODO: 实现 Token 刷新逻辑
        // 1. 验证 Refresh Token 的有效性
        // 2. 从 Token 中解析用户信息
        // 3. 生成新的 Access Token
        // 4. 返回新 Token

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("message", "Token 刷新成功");
        response.put("data", Map.of(
                "token", generateMockToken(null),
                "expiresIn", 86400
        ));

        return ResponseEntity.ok(response);
    }

    /**
     * 获取当前用户信息
     *
     * 需要在请求头中携带有效的 Token：
     * GET /api/auth/me
     * Authorization: Bearer <token>
     *
     * @param authentication 当前认证信息（由 Spring Security 自动注入）
     * @return 用户信息
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 401);
            errorResponse.put("message", "未认证");
            return ResponseEntity.status(401).body(errorResponse);
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", userDetails.getUsername());
        userInfo.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("data", userInfo);

        return ResponseEntity.ok(response);
    }

    // ==================== 辅助方法（示例实现）====================

    /**
     * 生成模拟 Token（仅用于演示）
     * 实际项目中应使用 JWT 库生成真实的 Token
     */
    private String generateMockToken(UserDetails userDetails) {
        // TODO: 使用 JwtUtil.generateToken(userDetails)
        return "mock_jwt_token_" + System.currentTimeMillis();
    }

    private String generateMockRefreshToken(UserDetails userDetails) {
        // TODO: 使用 JwtUtil.generateRefreshToken(userDetails)
        return "mock_refresh_token_" + System.currentTimeMillis();
    }

    // ==================== 请求 DTO 类 ====================

    /**
     * 登录请求体
     */
    public static class LoginRequest {
        private String username;
        private String password;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    /**
     * 注册请求体
     */
    public static class RegisterRequest {
        private String username;
        private String password;
        private String email;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    /**
     * 刷新 Token 请求体
     */
    public static class RefreshTokenRequest {
        private String refreshToken;

        public String getRefreshToken() { return refreshToken; }
        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    }
}
