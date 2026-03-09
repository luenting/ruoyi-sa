package com.ruoyi.framework.config;

import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.stp.SaTokenInfo;
import cn.dev33.satoken.stp.StpUtil;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.framework.web.service.PermissionService;
import com.ruoyi.framework.web.service.SysPermissionService;
import com.ruoyi.system.service.ISysUserService;
import org.apache.http.auth.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.CorsFilter;
import com.ruoyi.framework.config.properties.PermitAllUrlProperties;
// 1. 注释掉若依原有JWT过滤器（核心改动1）
// import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;
import com.ruoyi.framework.security.handle.LogoutSuccessHandlerImpl;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * spring security配置（适配Sa-Token Pro，仅替换Token校验）
 */
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
public class SecurityConfig
{
    /**
     * 自定义用户认证逻辑
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * 退出处理类
     */
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;

    // 2. 注释掉若依原有JWT过滤器（核心改动2）
    // @Autowired
    // private JwtAuthenticationTokenFilter authenticationTokenFilter;

    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;

    /**
     * 允许匿名访问的地址
     */
    @Autowired
    private PermitAllUrlProperties permitAllUrl;

    /**
     * 身份验证实现（保留若依原有逻辑，解决注入问题）
     */
    @Bean
    public AuthenticationManager authenticationManager()
    {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        return new ProviderManager(daoAuthenticationProvider);
    }

    /**
     * 强散列哈希加密实现（保留）
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    /**
     * 3. 新增Sa-Token Pro过滤器（核心改动3）
     * 替换若依原有JWT过滤器，实现Token校验
     */
    @Bean
    public SaTokenProFilter saTokenProFilter(ISysUserService userService, SysPermissionService permissionService) {
        return new SaTokenProFilter(userService, permissionService);
    }

    /**
     * 安全规则配置（仅替换过滤器，其余保留）
     */
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity httpSecurity, SaTokenProFilter saTokenProFilter) throws Exception
    {
        return httpSecurity
                // CSRF禁用（保留）
                .csrf(csrf -> csrf.disable())
                // 禁用HTTP响应标头（保留）
                .headers((headersCustomizer) -> {
                    headersCustomizer.cacheControl(cache -> cache.disable()).frameOptions(options -> options.sameOrigin());
                })
                // 认证失败处理类（保留）
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                // 基于token，不需要session（保留）
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 匿名路径配置（保留）
                .authorizeHttpRequests((requests) -> {
                    permitAllUrl.getUrls().forEach(url -> requests.antMatchers(url).permitAll());
                    requests.antMatchers("/login", "/sso/**", "/register", "/captchaImage").permitAll()
                            .antMatchers(HttpMethod.GET, "/", "/*.html", "/**/*.html", "/**/*.css", "/**/*.js", "/profile/**").permitAll()
                            .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/*/api-docs", "/druid/**").permitAll()
                            .anyRequest().authenticated();
                })
                // 退出处理（保留）
                .logout(logout -> logout.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler))
                // ========== 核心替换：用Sa-Token过滤器替换JWT过滤器 ==========
                .addFilterBefore(saTokenProFilter, UsernamePasswordAuthenticationFilter.class)
                // 跨域过滤器（保留）
                .addFilterBefore(corsFilter, SaTokenProFilter.class)
                .addFilterBefore(corsFilter, LogoutFilter.class)
                .build();
    }

    /**
     * Sa-Token Pro过滤器（内部类，实现Token校验）
     */
    public static class SaTokenProFilter extends OncePerRequestFilter {

        private final ISysUserService userService;

        private final SysPermissionService permissionService;

        public SaTokenProFilter(ISysUserService userService, SysPermissionService permissionService) {
            this.userService = userService;
            this.permissionService = permissionService;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            StpUtil.checkLogin();
            // 校验通过，继续执行请求
            System.out.println("Sa-Token校验通过，登录ID：" + StpUtil.getLoginId());

            Object loginId = StpUtil.getLoginIdDefaultNull();
            LoginUser loginUser = new LoginUser();
            if (loginId != null) {
                SysUser sysUser = userService.selectUserByUserName(loginId.toString());
                // 1. 根据登录ID（用户名/用户ID）查询SysUser（替换成你项目的用户查询逻辑）
                // 2. 构建LoginUser对象（和若依原有结构一致）
                loginUser.setUserId(sysUser.getUserId());
//                loginUser.setUserName(sysUser.getUserName());
                loginUser.setUser(sysUser);
                // 3. 可补充角色/权限信息（根据需要）
                loginUser.setPermissions(permissionService.getMenuPermission(sysUser));
            }

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    loginUser,                // 主体（用户ID/用户名）
                    null,                   // 凭证（Token，可填null）
                    // 必须添加至少一个权限/角色，否则判定为未认证
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
            );
            // 存入上下文
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(request, response);
        }

        // 排除匿名路径（和若依配置对齐，避免校验无需登录的接口）
        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
            String path = request.getRequestURI();
            return path.contains("/login") || path.contains("/register") || path.contains("/captchaImage")
                    || path.contains("/swagger") || path.contains("/webjars") || path.contains("/druid")
                    || path.endsWith(".html") || path.endsWith(".css") || path.endsWith(".js")
                    || path.endsWith("/sso/doLoginByTicket") || path.endsWith("/sso/logout");
        }
    }
}