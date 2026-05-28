package com.solo.solo_one.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Spring Security 前后端分离配置类
 * <p>
 * 主要特性：
 * 1. 无状态认证（Stateless）- 使用 JWT Token
 * 2. 禁用 CSRF - REST API 不需要 CSRF 防护
 * 3. 启用 CORS - 支持跨域请求
 * 4. Session 策略为 STATELESS - 不创建 Session
 * 5. 自定义 JWT 过滤器 - 拦截请求验证 Token
 * 6. JSON 格式响应 - 统一返回格式
 * 7. 方法级安全控制 - 支持 @PreAuthorize 注解
 *
 * @author solo
 * @version 1.0
 */
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
public class SecurityWebConfig {

    /**
     * 核心安全过滤链配置（前后端分离版本）
     * <p>
     * 关键配置说明：
     * - sessionManagement: STATELESS 无状态模式
     * - csrf: 禁用 CSRF（JWT 本身已具备防篡改能力）
     * - cors: 启用跨域支持
     * - formLogin/logout: 禁用表单登录，使用 API 方式
     * - exceptionHandling: 返回 JSON 格式错误信息
     *
     * @param http HttpSecurity 对象
     * @return SecurityFilterChain 安全过滤链
     * @throws Exception 配置异常
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // ==================== 禁用 CSRF（前后端分离必需）====================
                // JWT Token 存储在 Authorization Header 中，不会自动携带，天然防止 CSRF
                .csrf(AbstractHttpConfigurer::disable)

                // ==================== CORS 跨域配置 ====================
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // ==================== Session 管理（无状态）====================
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 不创建 Session
                )

                // ==================== 授权配置 ====================
                .authorizeHttpRequests(auth -> auth
                        // 公开访问的路径（无需认证）
                        .requestMatchers(
                                "/api/auth/login",           // 登录接口
                                "/api/auth/register",        // 注册接口
                                "/api/auth/refresh-token",   // 刷新 Token 接口
                                "/api/public/**",            // 公共资源
                                "/swagger-ui/**",            // Swagger 文档
                                "/v3/api-docs/**",           // OpenAPI 文档
                                "/favicon.ico"               // 网站图标
                        ).permitAll()

                        // OPTIONS 请求预检（CORS 需要）
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 管理员专属接口
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // 需要认证的用户接口
                        .requestMatchers("/api/user/**").hasAnyRole("ADMIN", "USER")

                        // 其他所有 API 都需要认证
                        .anyRequest().authenticated()
                )

                // ==================== 禁用表单登录和登出 ====================
                // 前后端分离项目不使用表单登录，而是通过 API 接口
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                // ==================== 添加 JWT 认证过滤器 ====================
                // 在用户名密码认证过滤器之前执行
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // ==================== 异常处理（返回 JSON）====================
                .exceptionHandling(exception -> exception
                        // 未认证时的处理（401）
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setCharacterEncoding("UTF-8");
                            // 方式 1: 简单固定响应
                            response.getWriter().write("{\"code\":401,\"message\":\"未认证，请先登录\"}");

                            // 方式 2: 使用 String.format 支持动态数据
                            // String json = String.format(
                            //     "{\"code\":401,\"message\":\"%s\",\"timestamp\":%d,\"path\":\"%s\"}",
                            //     "未认证，请先登录",
                            //     System.currentTimeMillis(),
                            //     request.getRequestURI()
                            // );
                            // response.getWriter().write(json);

                            // 方式 3: 使用文本块（Java 15+，更清晰）
                            // String json = """
                            //     {
                            //         "code": 401,
                            //         "message": "未认证，请先登录",
                            //         "timestamp": %d,
                            //         "path": "%s"
                            //     }
                            //     """.formatted(System.currentTimeMillis(), request.getRequestURI());
                            // response.getWriter().write(json);
                        })

                        // 权限不足时的处理（403）
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setCharacterEncoding("UTF-8");
                            response.getWriter().write("{\"code\":403,\"message\":\"权限不足，无法访问该资源\"}");

//                            Map<String, Object> errorResponse = new HashMap<>();
//                            errorResponse.put("code", 403);
//                            errorResponse.put("message", "权限不足，无法访问该资源");
//                            errorResponse.put("timestamp", System.currentTimeMillis());
//                            response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
                        })
                );

        return http.build();
    }

    /**
     * JWT 认证过滤器
     *
     * 工作流程：
     * 1. 从请求头中提取 JWT Token（Authorization: Bearer <token>）
     * 2. 验证 Token 的有效性和过期时间
     * 3. 从 Token 中解析用户信息和权限
     * 4. 将认证信息存入 SecurityContext
     * 5. 继续执行后续过滤器
     *
     * @return OncePerRequestFilter JWT 过滤器
     */
    @Bean
    public OncePerRequestFilter jwtAuthenticationFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain)
                    throws ServletException, IOException {

                // 从请求头中获取 Token
                String authorizationHeader = request.getHeader("Authorization");

                if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                    String token = authorizationHeader.substring(7);  // 去掉 "Bearer " 前缀

                    try {
                        // TODO: 在这里实现 JWT Token 验证逻辑
                        // 1. 验证 Token 签名
                        // 2. 检查 Token 是否过期
                        // 3. 从 Token 中解析用户名和权限

                        // 示例：假设从 Token 中解析出用户名
                        String username = parseUsernameFromToken(token);

                        if (username != null && isTokenValid(token, username)) {
                            // 加载用户详情（从数据库或缓存）
                            UserDetails userDetails = userDetailsService().loadUserByUsername(username);

                            // 创建认证对象
                            UsernamePasswordAuthenticationToken authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            userDetails,
                                            null,  // 凭证设为 null（已认证）
                                            userDetails.getAuthorities()
                                    );

                            // 设置额外信息
                            authentication.setDetails(
                                    new WebAuthenticationDetailsSource()
                                            .buildDetails(request)
                            );

                            // 将认证信息存入 SecurityContext
                            org.springframework.security.core.context.SecurityContextHolder
                                    .getContext()
                                    .setAuthentication(authentication);
                        }
                    } catch (Exception e) {
                        // Token 无效或解析失败，记录日志
                        System.err.println("JWT Token 验证失败: " + e.getMessage());
                    }
                }

                // 继续执行后续过滤器
                filterChain.doFilter(request, response);
            }

            /**
             * 从 Token 中解析用户名（示例实现）
             * 实际项目中应使用 JWT 库（如 jjwt、auth0-jwt）
             */
            private String parseUsernameFromToken(String token) {
                // TODO: 使用 JWT 库解析 Token
                // 示例：return Jwts.parserBuilder()
                //              .setSigningKey(secretKey)
                //              .build()
                //              .parseClaimsJws(token)
                //              .getBody()
                //              .getSubject();
                return "test";  // 示例返回
            }

            /**
             * 验证 Token 是否有效（示例实现）
             */
            private boolean isTokenValid(String token, String username) {
                // TODO: 实现 Token 验证逻辑
                // 1. 检查签名是否正确
                // 2. 检查是否过期
                // 3. 检查是否在黑名单中
                return true;  // 示例返回
            }
        };
    }

    /**
     * CORS 跨域配置
     *
     * 前后端分离项目中，前端和后端通常部署在不同域名/端口上，
     * 必须配置 CORS 才能正常通信。
     *
     * @return CorsConfigurationSource CORS 配置源
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 允许的源（前端地址）
        // 生产环境应该指定具体的域名，避免使用 "*"
        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000",      // React/Vue 开发服务器
                "http://localhost:5173",      // Vite 开发服务器
                "https://yourdomain.com"      // 生产环境域名
        ));

        // 允许的 HTTP 方法
        configuration.setAllowedMethods(List.of(
                "GET",     // 查询
                "POST",    // 创建
                "PUT",     // 更新
                "DELETE",  // 删除
                "PATCH",   // 部分更新
                "OPTIONS"  // 预检请求
        ));

        // 允许的请求头
        configuration.setAllowedHeaders(List.of("*"));

        // 暴露给浏览器的响应头（允许前端访问的头部）
        configuration.setExposedHeaders(List.of(
                "Authorization",     // JWT Token
                "X-Total-Count",     // 分页总数
                "X-Page-Number"      // 页码
        ));

        // 是否允许携带凭证（Cookie、Authorization 头等）
        // 注意：当 allowCredentials 为 true 时，allowedOrigins 不能使用 "*"
        configuration.setAllowCredentials(true);

        // 预检请求的缓存时间（秒）
        // 浏览器在此时间内不会再次发送 OPTIONS 请求
        configuration.setMaxAge(3600L);

        // 应用配置到所有路径
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * 密码编码器
     *
     * 使用 BCrypt 算法加密密码：
     * - 单向哈希，不可逆
     * - 自动加盐，防止彩虹表攻击
     * - strength 参数越大越安全（但也越慢），范围 4-31，默认 10
     *
     * @return PasswordEncoder 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * 认证管理器
     *
     * 用于在登录接口中进行用户认证
     *
     * @param authenticationConfiguration 认证配置
     * @return AuthenticationManager 认证管理器
     * @throws Exception 配置异常
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * 用户详情服务（内存实现 - 仅用于演示）
     *
     * ⚠️ 生产环境应该使用数据库实现！
     *
     * @return UserDetailsService 用户详情服务
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 管理员用户
        org.springframework.security.core.userdetails.User admin =
                (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("admin123"))
                        .roles("ADMIN")
                        .authorities("read", "write", "delete")
                        .build();

        // 普通用户
        org.springframework.security.core.userdetails.User user =
                (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("user123"))
                        .roles("USER")
                        .authorities("read")
                        .build();

        return new org.springframework.security.provisioning.InMemoryUserDetailsManager(admin, user);
    }

    // ==================== 以下为可选的高级配置 ====================

    /**
     * 数据库实现的用户详情服务（示例）
     *
     * 在实际项目中，应该创建这样的 Service：
     *
     * @Service
     * public class CustomUserDetailsService implements UserDetailsService {
     *
     *     @Autowired
     *     private UserRepository userRepository;
     *
     *     @Override
     *     public UserDetails loadUserByUsername(String username)
     *             throws UsernameNotFoundException {
     *
     *         User user = userRepository.findByUsername(username)
     *             .orElseThrow(() ->
     *                 new UsernameNotFoundException("用户不存在: " + username)
     *             );
     *
     *         return org.springframework.security.core.userdetails.User.builder()
     *             .username(user.getUsername())
     *             .password(user.getPassword())
     *             .roles(user.getRoles().toArray(new String[0]))
     *             .authorities(user.getPermissions().toArray(new String[0]))
     *             .accountExpired(!user.isAccountNonExpired())
     *             .accountLocked(!user.isAccountNonLocked())
     *             .credentialsExpired(!user.isCredentialsNonExpired())
     *             .disabled(!user.isEnabled())
     *             .build();
     *     }
     * }
     */

    /**
     * JWT Token 工具类（示例接口定义）
     *
     * 建议创建一个独立的 JwtUtil 类来处理 Token 相关操作：
     *
     * @Component
     * public class JwtUtil {
     *
     *     private final String secretKey;
     *     private final long expirationTime;
     *
     *     public JwtUtil(@Value("${jwt.secret}") String secretKey,
     *                   @Value("${jwt.expiration}") long expirationTime) {
     *         this.secretKey = secretKey;
     *         this.expirationTime = expirationTime;
     *     }
     *
     *     // 生成 Token
     *     public String generateToken(UserDetails userDetails) {
     *         Map<String, Object> claims = new HashMap<>();
     *         claims.put("roles", userDetails.getAuthorities().stream()
     *             .map(GrantedAuthority::getAuthority)
     *             .collect(Collectors.toList()));
     *
     *         return Jwts.builder()
     *             .setClaims(claims)
     *             .setSubject(userDetails.getUsername())
     *             .setIssuedAt(new Date())
     *             .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
     *             .signWith(SignatureAlgorithm.HS256, secretKey)
     *             .compact();
     *     }
     *
     *     // 验证 Token
     *     public boolean validateToken(String token) {
     *         try {
     *             Jwts.parserBuilder()
     *                 .setSigningKey(secretKey)
     *                 .build()
     *                 .parseClaimsJws(token);
     *             return true;
     *         } catch (JwtException | IllegalArgumentException e) {
     *             return false;
     *         }
     *     }
     *
     *     // 从 Token 中获取用户名
     *     public String getUsernameFromToken(String token) {
     *         return Jwts.parserBuilder()
     *             .setSigningKey(secretKey)
     *             .build()
     *             .parseClaimsJws(token)
     *             .getBody()
     *             .getSubject();
     *     }
     *
     *     // 从 Token 中获取权限
     *     public List<String> getRolesFromToken(String token) {
     *         Claims claims = Jwts.parserBuilder()
     *             .setSigningKey(secretKey)
     *             .build()
     *             .parseClaimsJws(token)
     *             .getBody();
     *
     *         return claims.get("roles", List.class);
     *     }
     * }
     */
}
