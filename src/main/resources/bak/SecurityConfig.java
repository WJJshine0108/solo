package bak;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Spring Security 安全配置类
 * 主要功能：
 * 1. 配置 HTTP 安全策略（授权、认证）
 * 2. 配置用户详情服务（内存/数据库）
 * 3. 配置密码编码器
 * 4. 配置 CORS 跨域支持
 * 5. 配置 CSRF 防护
 *
 * @author solo
 * @version 1.0
 */
//@Configuration
//@EnableWebSecurity
public class SecurityConfig {

    /**
     * 核心安全过滤链配置
     * 这是 Spring Security 的核心配置方法，用于定义：
     * - 哪些资源需要保护
     * - 哪些资源可以公开访问
     * - 使用什么方式进行认证
     * - 如何处理异常
     *
     * @param http HttpSecurity 对象，用于构建安全配置
     * @return SecurityFilterChain 安全过滤链
     * @throws Exception 配置异常
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // ==================== 授权配置 ====================
                .authorizeHttpRequests(auth -> auth
                        // 允许所有人访问的公开路径（无需认证）
                        // 示例：/public/**, /api/public/**, /css/**, /js/**, /images/**
                        .requestMatchers("/public/**", "/api/public/**", "/css/**", "/js/**", "/images/**").permitAll()

                        // 允许匿名访问的路径（无需登录，但可以有身份）
                        // 示例：登录页面、注册页面
                        .requestMatchers("/login", "/register", "/api/auth/**").anonymous()

                        // 只允许特定角色访问的路径
                        // hasRole("ADMIN") 表示需要 ADMIN 角色（自动添加 ROLE_ 前缀）
                        // hasAnyRole("ADMIN", "USER") 表示需要 ADMIN 或 USER 角色
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("ADMIN", "USER")

                        // 基于权限的访问控制
                        // hasAuthority("read") 表示需要 read 权限
                        // hasAnyAuthority("read", "write") 表示需要 read 或 write 权限
                        .requestMatchers("/api/data/**").hasAuthority("read")

                        // IP 地址限制（可选）
                        // .requestMatchers("/internal/**").hasIpAddress("192.168.1.0/24")

                        // 其他所有请求都需要认证
                        .anyRequest().authenticated()
                )

                // ==================== 表单登录配置 ====================
                .formLogin(form -> form
                        // 自定义登录页面路径
                        .loginPage("/login")

                        // 登录处理 URL（POST 请求提交到此地址）
                        .loginProcessingUrl("/perform_login")

                        // 登录成功后的默认跳转页面
                        .defaultSuccessUrl("/dashboard", true)  // true 表示总是跳转到此页面

                        // 登录成功后的自定义处理器（可选，用于返回 JSON）
                        // .successHandler((request, response, authentication) -> {
                        //     response.setContentType("application/json;charset=UTF-8");
                        //     response.getWriter().write("{\"code\":200,\"message\":\"登录成功\"}");
                        // })

                        // 登录失败后的跳转页面
                        .failureUrl("/login?error=true")

                        // 登录失败的自定义处理器（可选）
                        // .failureHandler((request, response, exception) -> {
                        //     response.setContentType("application/json;charset=UTF-8");
                        //     response.getWriter().write("{\"code\":401,\"message\":\"登录失败: \" + exception.getMessage()}");
                        // })

                        // 用户名和密码的参数名（默认为 username 和 password）
                        .usernameParameter("username")
                        .passwordParameter("password")

                        // 允许未认证用户访问登录页面
                        .permitAll()
                )

                // ==================== 登出配置 ====================
                .logout(logout -> logout
                        // 登出请求的 URL
                        .logoutUrl("/logout")

                        // 登出成功后跳转的页面
                        .logoutSuccessUrl("/login?logout=true")

                        // 使 Session 失效
                        .invalidateHttpSession(true)

                        // 清除认证信息
                        .clearAuthentication(true)

                        // 删除 Cookie
                        .deleteCookies("JSESSIONID", "remember-me")

                        // 登出成功的自定义处理器（可选）
                        // .logoutSuccessHandler((request, response, authentication) -> {
                        //     response.setContentType("application/json;charset=UTF-8");
                        //     response.getWriter().write("{\"code\":200,\"message\":\"登出成功\"}");
                        // })

                        .permitAll()
                )

                // ==================== Remember Me 记住我配置 ====================
                .rememberMe(remember -> remember
                                // remember-me Cookie 的名称
                                .rememberMeParameter("remember-me")

                                // Token 有效期（秒），默认 2 周
                                .tokenValiditySeconds(7 * 24 * 60 * 60)  // 7 天

                                // 用于加密 Token 的密钥（生产环境应使用环境变量）
                                .key("mySecretKeyForRememberMe")

                        // 使用持久化 Token（存储到数据库）
                        // .tokenRepository(persistentTokenRepository())
                )

                // ==================== Session 管理配置 ====================
                .sessionManagement(session -> session
                        // Session 创建策略：
                        // ALWAYS: 总是创建 Session
                        // IF_REQUIRED: 需要时创建（默认）
                        // NEVER: 不主动创建，但如果已存在则使用
                        // STATELESS: 无状态，不使用 Session（适用于 REST API + JWT）
                        .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)

                        // 无效 Session 的跳转页面
                        .invalidSessionUrl("/login?invalid=true")

                        // 最大并发会话数（防止同一用户多次登录）
                        .maximumSessions(1)

                        // 达到最大会话数时的行为：
                        // true: 阻止新登录
                        // false: 使旧会话失效（踢掉之前的用户）
                        .maxSessionsPreventsLogin(false)

                        // Session 过期后的跳转页面
                        .expiredUrl("/login?expired=true")
                )

                // ==================== CSRF 防护配置 ====================
                .csrf(csrf -> csrf
                                // 启用 CSRF 防护（默认启用）
                                // 对于前后端分离项目，建议使用 Cookie 方式
                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

                                // 自定义 CSRF Token 请求处理器
                                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())

                        // 排除不需要 CSRF 防护的路径（通常是 GET 请求或公共 API）
                        // .ignoringRequestMatchers("/api/public/**", "/login")

                        // 对于 REST API，可以考虑禁用 CSRF（如果使用 JWT）
                        // .disable()
                )

                // ==================== CORS 跨域配置 ====================
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // ==================== HTTP Headers 安全配置 ====================
                .headers(headers -> headers
                        // Content-Security-Policy (CSP) - 防止 XSS 攻击
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
                        )

                        // X-Frame-Options - 防止点击劫持
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)  // 允许同源嵌入

                        // X-Content-Type-Options - 防止 MIME 类型嗅探
                        .contentTypeOptions(Customizer.withDefaults())

                        // Strict-Transport-Security (HSTS) - 强制 HTTPS
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)  // 1 年
                                .preload(true)
                        )

                        // Referrer-Policy - 控制 Referer 信息（使用新的 API）
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))

                        // Permissions-Policy - 控制浏览器功能权限（使用自定义 HeaderWriter）
                        .addHeaderWriter((request, response) ->
                                response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                        )
                )

                // ==================== 异常处理配置 ====================
                .exceptionHandling(exception -> exception
                        // 未认证时的处理（401）
                        .authenticationEntryPoint((request, response, authException) -> {
                            // 对于 REST API，返回 JSON
                            if (request.getRequestURI().startsWith("/api/")) {
                                response.setContentType("application/json;charset=UTF-8");
                                response.setStatus(401);
                                response.getWriter().write("{\"code\":401,\"message\":\"未认证，请先登录\"}");
                            } else {
                                // 对于网页，重定向到登录页
                                response.sendRedirect("/login");
                            }
                        })

                        // 权限不足时的处理（403）
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            // 对于 REST API，返回 JSON
                            if (request.getRequestURI().startsWith("/api/")) {
                                response.setContentType("application/json;charset=UTF-8");
                                response.setStatus(403);
                                response.getWriter().write("{\"code\":403,\"message\":\"权限不足，无法访问\"}");
                            } else {
                                // 对于网页，重定向到错误页
                                response.sendRedirect("/access-denied");
                            }
                        })
                );

        return http.build();
    }

    /**
     * CORS 跨域配置源
     * 用于配置允许哪些域名、方法、头信息进行跨域访问
     *
     * @return CorsConfigurationSource CORS 配置源
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 允许的源（域名）
        // configuration.setAllowedOrigins(List.of("http://localhost:3000", "https://example.com"));
        configuration.setAllowedOrigins(List.of("*"));  // 允许所有源（生产环境建议指定具体域名）

        // 允许的 HTTP 方法
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // 允许的请求头
        configuration.setAllowedHeaders(List.of("*"));  // 允许所有头

        // 暴露给浏览器的响应头
        configuration.setExposedHeaders(List.of("Authorization", "X-CSRF-TOKEN"));

        // 是否允许携带凭证（Cookie、Authorization 头等）
        configuration.setAllowCredentials(true);

        // 预检请求的缓存时间（秒）
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 对所有路径应用此 CORS 配置
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * 密码编码器
     * 使用 BCrypt 算法对密码进行加密
     * BCrypt 是一种安全的单向哈希算法，带有盐值，防止彩虹表攻击
     *
     * @return PasswordEncoder 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);  // strength=12，默认是 10，值越大越安全但也越慢
    }

    /**
     * 用户详情服务（内存实现）
     * 这是一个简单的内存用户存储，适用于开发和测试
     * 生产环境应该使用数据库实现（UserDetailsService + JPA/MyBatis）
     *
     * @return UserDetailsService 用户详情服务
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 创建管理员用户
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))  // 实际项目中密码应来自数据库
                .roles("ADMIN")  // 自动添加 ROLE_ 前缀，即 ROLE_ADMIN
                .authorities("read", "write", "delete")  // 额外权限
                .accountExpired(false)  // 账户是否过期
                .accountLocked(false)   // 账户是否锁定
                .credentialsExpired(false)  // 凭证是否过期
                .disabled(false)  // 账户是否禁用
                .build();

        // 创建普通用户
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user123"))
                .roles("USER")  // ROLE_USER
                .authorities("read")
                .build();

        // 创建测试用户
        UserDetails test = User.builder()
                .username("test")
                .password(passwordEncoder().encode("test123"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user, test);
    }

    // ==================== 以下为可选的高级配置 ====================

    /**
     * 持久化 Token 仓库（用于 Remember Me 功能）
     * 将 remember-me token 存储到数据库中，比默认的更安全
     * 需要创建 persistent_logins 表：
     * CREATE TABLE persistent_logins (
     *     username VARCHAR(64) NOT NULL,
     *     series VARCHAR(64) PRIMARY KEY,
     *     token VARCHAR(64) NOT NULL,
     *     last_used TIMESTAMP NOT NULL
     * );
     *
     * @return PersistentTokenRepository 持久化 Token 仓库
     */
/*    @Bean
    public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);
        // 首次运行时自动创建表（后续应注释掉）
        // repository.setCreateTableOnStartup(true);
        return repository;
    }*/

    /**
     * 自定义认证管理器（可选）
     * 如果需要自定义认证逻辑（如验证码、多因素认证等），可以配置此 Bean
     *
     * @param userDetailsService 用户详情服务
     * @return AuthenticationManager 认证管理器
     */
/*    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        // 添加额外的认证检查（如验证码）
        provider.setPreAuthenticationChecks(userDetails -> {
            if (!userDetails.isAccountNonLocked()) {
                throw new LockedException("账户已被锁定");
            }
        });

        return new ProviderManager(provider);
    }*/

    /**
     * 方法级安全配置（可选）
     * 如果需要在 Service 层使用方法注解（@PreAuthorize, @PostAuthorize 等），
     * 需要在启动类或配置类上添加 @EnableMethodSecurity 注解
     * 示例用法：
     * @ PreAuthorize("hasRole('ADMIN')")
     * public void deleteUser(Long id) { ... }
     * @ PreAuthorize("hasAuthority('read') and #userId == authentication.principal.id")
     * public User getUser(Long userId) { ... }
     */
    public User getUser(Long userId) {
        return null;
    }
}

