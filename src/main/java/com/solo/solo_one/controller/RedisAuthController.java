package com.solo.solo_one.controller;

import com.solo.solo_one.config.SecurityRedisConfig;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
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
 * 认证控制器（Redis 双 Token 版本）
 * <p>
 * 提供基于 Redis 的双 Token 认证接口：
 * - 登录：返回 Access Token + Refresh Token
 * - 刷新：使用 Refresh Token 获取新的 Access Token
 * - 登出：使 Token 失效
 * - 获取当前用户信息
 *
 * @author solo
 * @version 1.0
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class RedisAuthController {

    private final AuthenticationManager authenticationManager;
    private final SecurityRedisConfig securityRedisConfig;

    /**
     * 用户登录
     * <p>
     * 请求示例：
     * POST /api/auth/login
     * Content-Type: application/json
     * <p>
     * {
     *   "username": "admin",
     *   "password": "admin123"
     * }
     * <p>
     * 响应示例：
     * {
     *   "code": 200,
     *   "message": "登录成功",
     *   "data": {
     *     "accessToken": "xxx",
     *     "refreshToken": "yyy",
     *     "accessExpiresIn": 1800,
     *     "refreshExpiresIn": 604800,
     *     "user": {
     *       "username": "admin",
     *       "roles": ["ROLE_ADMIN"]
     *     }
     *   }
     * }
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        try {
            // 1. 验证用户名和密码
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            // 2. 获取用户信息
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> roles = null;
            if (userDetails != null) {
                roles = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
            }

            // 3. 生成双 Token（存储在 Redis 中）
            SecurityRedisConfig.TokenPair tokenPair =
                    null;
            if (userDetails != null) {
                tokenPair = securityRedisConfig.generateTokens(userDetails.getUsername(), roles);
            }

            // 4. 构建响应
            Map<String, Object> data = new HashMap<>();
            if (tokenPair != null) {
                data.put("accessToken", tokenPair.getAccessToken());
            }
            if (tokenPair != null) {
                data.put("refreshToken", tokenPair.getRefreshToken());
            }
            if (tokenPair != null) {
                data.put("accessExpiresIn", tokenPair.getAccessExpiresIn());
            }
            if (tokenPair != null) {
                data.put("refreshExpiresIn", tokenPair.getRefreshExpiresIn());
            }

            Map<String, Object> userInfo = new HashMap<>();
            if (userDetails != null) {
                userInfo.put("username", userDetails.getUsername());
            }
            userInfo.put("roles", roles);
            data.put("user", userInfo);

            Map<String, Object> response = new HashMap<>();
            response.put("code", 200);
            response.put("message", "登录成功");
            response.put("data", data);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 401);
            errorResponse.put("message", "用户名或密码错误");
            errorResponse.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.status(401).body(errorResponse);
        }
    }

    /**
     * 刷新 Access Token
     * <p>
     * 请求示例：
     * POST /api/auth/refresh-token
     * Content-Type: application/json
     * <p>
     * {
     *   "refreshToken": "xxx"
     * }
     * <p>
     * 响应示例：
     * {
     *   "code": 200,
     *   "message": "Token 刷新成功",
     *   "data": {
     *     "accessToken": "new_xxx",
     *     "refreshToken": "new_yyy",
     *     "accessExpiresIn": 1800,
     *     "refreshExpiresIn": 604800
     *   }
     * }
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            // 使用 Refresh Token 获取新的 Token Pair
            SecurityRedisConfig.TokenPair tokenPair =
                    securityRedisConfig.refreshAccessToken(request.getRefreshToken());

            Map<String, Object> response = getStringObjectMap(tokenPair);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 401);
            errorResponse.put("message", "Token 刷新失败: " + e.getMessage());
            errorResponse.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.status(401).body(errorResponse);
        }
    }

    private static @NonNull Map<String, Object> getStringObjectMap(SecurityRedisConfig.@NonNull TokenPair tokenPair) {
        Map<String, Object> data = new HashMap<>();
        data.put("accessToken", tokenPair.getAccessToken());
        data.put("refreshToken", tokenPair.getRefreshToken());
        data.put("accessExpiresIn", tokenPair.getAccessExpiresIn());
        data.put("refreshExpiresIn", tokenPair.getRefreshExpiresIn());

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("message", "Token 刷新成功");
        response.put("data", data);
        return response;
    }

    /**
     * 用户登出
     * <p>
     * 请求示例：
     * POST /api/auth/logout
     * Headers: Authorization: Bearer <accessToken>
     * <p>
     * {
     *   "refreshToken": "xxx"
     * }
     * <p>
     * 响应示例：
     * {
     *   "code": 200,
     *   "message": "登出成功"
     * }
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(
            @RequestHeader("Authorization") String authorization,
            @RequestBody LogoutRequest request) {

        String accessToken = authorization.substring(7);  // 去掉 "Bearer "

        // 使 Token 失效
        securityRedisConfig.invalidateTokens(accessToken, request.getRefreshToken());

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("message", "登出成功");

        return ResponseEntity.ok(response);
    }

    /**
     * 强制登出所有设备
     * <p>
     * POST /api/auth/logout-all
     * Headers: Authorization: Bearer <accessToken>
     * <p>
     * {
     *   "userId": "xxx"
     * }
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Map<String, Object>> logoutAll(@RequestBody LogoutAllRequest request) {
        try {
            // 使该用户的所有 Token 失效
            securityRedisConfig.invalidateUserTokens(request.getUserId());

            Map<String, Object> response = new HashMap<>();
            response.put("code", 200);
            response.put("message", "已登出所有设备");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 500);
            errorResponse.put("message", "操作失败: " + e.getMessage());
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 获取当前用户信息
     * <p>
     * GET /api/auth/me
     * Headers: Authorization: Bearer <accessToken>
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", 401);
            errorResponse.put("message", "未认证");
            return ResponseEntity.status(401).body(errorResponse);
        }

        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", username);
        userInfo.put("roles", roles);

        Map<String, Object> response = new HashMap<>();
        response.put("code", 200);
        response.put("data", userInfo);

        return ResponseEntity.ok(response);
    }

    // ==================== 请求 DTO ====================

    @Data
    public static class LoginRequest {
        private String username;
        private String password;
    }

    @Data
    public static class RefreshTokenRequest {
        private String refreshToken;
    }

    @Data
    public static class LogoutRequest {
        private String refreshToken;
    }

    @Data
    public static class LogoutAllRequest {
        private String userId;
    }
}
