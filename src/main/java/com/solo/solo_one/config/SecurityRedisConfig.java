package com.solo.solo_one.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Spring Security + Redis 双 Token 认证配置
 * <p>
 * 双 Token 机制说明：
 * ┌─────────────────────────────────────────────────────┐
 * │  Access Token（访问令牌）                             │
 * │  - 有效期短：15-30 分钟                              │
 * │  - 存储在 Redis：key = "access:{token}"              │
 * │  - 每次请求都验证                                     │
 * │  - 包含用户信息和权限                                 │
 * ├─────────────────────────────────────────────────────┤
 * │  Refresh Token（刷新令牌）                            │
 * │  - 有效期长：7-30 天                                 │
 * │  - 存储在 Redis：key = "refresh:{token}"             │
 * │  - 仅在 Access Token 过期时使用                       │
 * │  - 用于获取新的 Access Token                          │
 * └─────────────────────────────────────────────────────┘
 * <p>
 * Redis 存储结构：
 * - access:{token} -> UserInfo (15分钟过期)
 * - refresh:{token} -> UserInfo (7天过期)
 * - user:tokens:{userId} -> Set<Token> (用户的所有有效 Token)
 * - blacklist:{token} -> String (黑名单 Token，直到过期)
 * <p>
 * 优势：
 * 1. 安全性高：Access Token 短期有效，泄露风险低
 * 2. 可控制：可随时使 Token 失效（删除 Redis key）
 * 3. 支持单点登录：可管理用户的所有设备 Token
 * 4. 性能优秀：Redis 快速验证，无需数据库查询
 *
 * @author solo
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityRedisConfig {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    // Token 有效期配置
    private static final long ACCESS_TOKEN_EXPIRE = 30 * 60;  // 30 分钟（秒）
    private static final long REFRESH_TOKEN_EXPIRE = 7 * 24 * 60 * 60;  // 7 天（秒）

    // Redis Key 前缀
    private static final String ACCESS_TOKEN_PREFIX = "access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";
    private static final String USER_TOKENS_PREFIX = "user:tokens:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    /**
     * 核心安全过滤链配置
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http
                // 禁用 CSRF（前后端分离）
                .csrf(AbstractHttpConfigurer::disable)

                // CORS 跨域配置
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 无状态 Session
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 授权配置
                .authorizeHttpRequests(auth -> auth
                        // 公开接口
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/refresh-token",
                                "/api/public/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // OPTIONS 预检请求
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 管理员接口
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // 用户接口
                        .requestMatchers("/api/user/**").hasAnyRole("ADMIN", "USER")

                        // 其他接口需要认证
                        .anyRequest().authenticated()
                )

                // 禁用表单登录
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                // 添加 JWT 过滤器
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // 异常处理
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> writeJsonResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                                401, "未认证，请先登录", request.getRequestURI()))
                        .accessDeniedHandler((request, response, accessDeniedException) -> writeJsonResponse(response, HttpServletResponse.SC_FORBIDDEN,
                                403, "权限不足，无法访问", request.getRequestURI()))
                );

        return http.build();
    }

    /**
     * JWT 认证过滤器（从 Redis 验证 Token）
     * <p>
     * 工作流程：
     * 1. 从请求头提取 Access Token
     * 2. 检查是否在黑名单中
     * 3. 从 Redis 中查询 Token 信息
     * 4. 验证 Token 是否有效
     * 5. 设置认证信息到 SecurityContext
     */
    @Bean
    public OncePerRequestFilter jwtAuthenticationFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(@NonNull HttpServletRequest request,
                                            @NonNull HttpServletResponse response,
                                            @NonNull FilterChain filterChain)
                    throws ServletException, IOException {

                String authorizationHeader = request.getHeader("Authorization");

                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    String accessToken = authorizationHeader.substring(7);
                    accessToken = "accessToken".concat(accessToken);
                    try {
                        // 1. 检查 Token 是否在黑名单中
                        if (isTokenBlacklisted(accessToken)) {
                            throw new SecurityException("Token 已被撤销");
                        }

                        // 2. 从 Redis 中获取 Token 信息
                        UserInfo userInfo = getAccessTokenInfo(accessToken);

                        if (userInfo != null && !isTokenExpired(userInfo.getExpireTime())) {
                            // 3. 创建认证对象
                            List<GrantedAuthority> authorities = userInfo.getRoles().stream()
                                    .map(role -> (GrantedAuthority) () -> role)
                                    .collect(Collectors.toList());

                            UsernamePasswordAuthenticationToken authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            userInfo.getUsername(),
                                            null,
                                            authorities
                                    );

                            authentication.setDetails(userInfo);

                            // 4. 设置到 SecurityContext
                            SecurityContextHolder
                                    .getContext()
                                    .setAuthentication(authentication);
                        }
                    } catch (Exception e) {
                        System.err.println("Token 验证失败: " + e.getMessage());
                    }
                }

                filterChain.doFilter(request, response);
            }
        };
    }

    /**
     * 生成 Access Token 和 Refresh Token
     *
     * @param username 用户名
     * @param roles 角色列表
     * @return TokenPair 包含 Access Token 和 Refresh Token
     */
    public TokenPair generateTokens(String username, List<String> roles) {
        String userId = UUID.randomUUID().toString();
        long currentTime = System.currentTimeMillis();

        // 生成 Access Token
        String accessToken = "accessToken".concat(createToken());
        UserInfo accessUserInfo = new UserInfo();
        accessUserInfo.setUserId(userId);
        accessUserInfo.setUsername(username);
        accessUserInfo.setRoles(roles);
        accessUserInfo.setIssueTime(currentTime);
        accessUserInfo.setExpireTime(currentTime + ACCESS_TOKEN_EXPIRE * 1000);

        // 生成 Refresh Token
        String refreshToken = "refreshToken".concat(createToken());
        UserInfo refreshUserInfo = new UserInfo();
        refreshUserInfo.setUserId(userId);
        refreshUserInfo.setUsername(username);
        refreshUserInfo.setRoles(roles);
        refreshUserInfo.setIssueTime(currentTime);
        refreshUserInfo.setExpireTime(currentTime + REFRESH_TOKEN_EXPIRE * 1000);

        // 存储到 Redis
        saveAccessToken(accessToken, accessUserInfo);
        saveRefreshToken(refreshToken, refreshUserInfo);
        saveUserTokenMapping(userId, accessToken, refreshToken);

        return new TokenPair(accessToken, refreshToken, ACCESS_TOKEN_EXPIRE, REFRESH_TOKEN_EXPIRE);
    }

    public String createToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 刷新 Access Token
     *
     * @param refreshToken 刷新令牌
     * @return 新的 TokenPair
     */
    public TokenPair refreshAccessToken(String refreshToken) {
        // 1. 验证 Refresh Token
        UserInfo userInfo = getRefreshTokenInfo(refreshToken);

        if (userInfo == null || isTokenExpired(userInfo.getExpireTime())) {
            throw new SecurityException("Refresh Token 无效或已过期");
        }

        // 2. 检查是否在黑名单中
        if (isTokenBlacklisted(refreshToken)) {
            throw new SecurityException("Refresh Token 已被撤销");
        }

        // 3. 删除旧的 Access Token（可选，实现单设备登录）
        invalidateUserTokens(userInfo.getUserId());

        // 4. 生成新的 Token Pair
        return generateTokens(userInfo.getUsername(), userInfo.getRoles());
    }

    /**
     * 使 Token 失效（登出）
     *
     * @param accessToken Access Token
     * @param refreshToken Refresh Token
     */
    public void invalidateTokens(String accessToken, String refreshToken) {
        // 1. 将 Token 加入黑名单
        addToBlacklist(accessToken);
        addToBlacklist(refreshToken);

        // 2. 从 Redis 中删除
        redisTemplate.delete(ACCESS_TOKEN_PREFIX + accessToken);
        redisTemplate.delete(REFRESH_TOKEN_PREFIX + refreshToken);
    }

    /**
     * 使指定用户的所有 Token 失效（强制登出所有设备）
     *
     * @param userId 用户 ID
     */
    public void invalidateUserTokens(String userId) {
        String key = USER_TOKENS_PREFIX + userId;
        Set<Object> tokens = redisTemplate.opsForSet().members(key);

        if (tokens != null) {
            for (Object token : tokens) {
                String tokenStr = token.toString();
                addToBlacklist(tokenStr);
                redisTemplate.delete(ACCESS_TOKEN_PREFIX + tokenStr);
                redisTemplate.delete(REFRESH_TOKEN_PREFIX + tokenStr);
            }
            redisTemplate.delete(key);
        }
    }

    // ==================== Redis 操作方法 ====================

    /**
     * 保存 Access Token 到 Redis
     */
    private void saveAccessToken(String token, UserInfo userInfo) {
        String key = ACCESS_TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, userInfo, ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
    }

    /**
     * 保存 Refresh Token 到 Redis
     */
    private void saveRefreshToken(String token, UserInfo userInfo) {
        String key = REFRESH_TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, userInfo, REFRESH_TOKEN_EXPIRE, TimeUnit.SECONDS);
    }

    /**
     * 保存用户与 Token 的映射关系
     */
    private void saveUserTokenMapping(String userId, String accessToken, String refreshToken) {
        String key = USER_TOKENS_PREFIX + userId;
        redisTemplate.opsForSet().add(key, accessToken, refreshToken);
        redisTemplate.expire(key, REFRESH_TOKEN_EXPIRE, TimeUnit.SECONDS);
    }

    /**
     * 从 Redis 获取 Access Token 信息
     */
    private UserInfo getAccessTokenInfo(String token) {
        String key = ACCESS_TOKEN_PREFIX + token;
        Object obj = redisTemplate.opsForValue().get(key);
        return obj instanceof UserInfo ? (UserInfo) obj : null;
    }

    /**
     * 从 Redis 获取 Refresh Token 信息
     */
    private UserInfo getRefreshTokenInfo(String token) {
        String key = REFRESH_TOKEN_PREFIX + token;
        Object obj = redisTemplate.opsForValue().get(key);
        return obj instanceof UserInfo ? (UserInfo) obj : null;
    }

    /**
     * 将 Token 加入黑名单
     */
    private void addToBlacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        // 黑名单有效期为 Token 的剩余有效期
        redisTemplate.opsForValue().set(key, "blacklisted", REFRESH_TOKEN_EXPIRE, TimeUnit.SECONDS);
    }

    /**
     * 检查 Token 是否在黑名单中
     */
    private boolean isTokenBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * 检查 Token 是否过期
     */
    private boolean isTokenExpired(long expireTime) {
        return System.currentTimeMillis() > expireTime;
    }

    // ==================== 辅助方法 ====================

    /**
     * 统一的 JSON 响应写入
     */
    private void writeJsonResponse(HttpServletResponse response, int httpStatus,
                                   int code, String message, String path) {
        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.setStatus(httpStatus);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("code", code);
            errorResponse.put("message", message);
            errorResponse.put("timestamp", System.currentTimeMillis());
            errorResponse.put("path", path);

            objectMapper.writeValue(response.getOutputStream(), errorResponse);
        } catch (IOException e) {
            System.err.println("写入 JSON 响应失败: " + e.getMessage());
        }
    }

    /**
     * CORS 配置
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
//                "http://localhost:3000",
//                "http://localhost:5173",
//                "https://yourdomain.com"
                "*"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * 认证管理器
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 用户详情服务（示例）
     */
    @Bean
    public UserDetailsService userDetailsService() {
        org.springframework.security.core.userdetails.User admin =
                (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin123"))
                        .roles("ADMIN")
                        .build();

        org.springframework.security.core.userdetails.User user =
                (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user123"))
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    // ==================== 数据类 ====================

    /**
     * Token 对（Access Token + Refresh Token）
     */
    @Data
    public static class TokenPair {
        private String accessToken;
        private String refreshToken;
        private long accessExpiresIn;
        private long refreshExpiresIn;

        public TokenPair(String accessToken, String refreshToken,
                         long accessExpiresIn, long refreshExpiresIn) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.accessExpiresIn = accessExpiresIn;
            this.refreshExpiresIn = refreshExpiresIn;
        }
    }

    /**
     * 用户信息（存储在 Redis 中）
     */
    @Data
    public static class UserInfo {
        private String userId;
        private String username;
        private List<String> roles;
        private Long issueTime;
        private Long expireTime;
    }
}
