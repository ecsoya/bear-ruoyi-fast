package com.github.ecsoya.bear.framework.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;

import com.github.ecsoya.bear.framework.config.properties.PermitAllUrlProperties;
import com.github.ecsoya.bear.framework.security.filter.JwtAuthenticationTokenFilter;
import com.github.ecsoya.bear.framework.security.handle.AuthenticationEntryPointImpl;
import com.github.ecsoya.bear.framework.security.handle.LogoutSuccessHandlerImpl;

/**
 * spring security配置
 * 
 * @author bearfast_ry
 */
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
public class SecurityConfig {
	private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

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

	/**
	 * token认证过滤器
	 */
	@Autowired
	private JwtAuthenticationTokenFilter authenticationTokenFilter;

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
	 * 身份验证实现
	 */
	@Bean
	public AuthenticationManager authenticationManager() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
		return new ProviderManager(daoAuthenticationProvider);
	}

	/**
	 * anyRequest | 匹配所有请求路径 access | SpringEl表达式结果为true时可以访问 anonymous | 匿名可以访问
	 * denyAll | 用户不能访问 fullyAuthenticated | 用户完全认证可以访问（非remember-me下自动登录）
	 * hasAnyAuthority | 如果有参数，参数表示权限，则其中任何一个权限可以访问 hasAnyRole |
	 * 如果有参数，参数表示角色，则其中任何一个角色可以访问 hasAuthority | 如果有参数，参数表示权限，则其权限可以访问 hasIpAddress
	 * | 如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问 hasRole | 如果有参数，参数表示角色，则其角色可以访问 permitAll
	 * | 用户可以任意访问 rememberMe | 允许通过remember-me登录的用户访问 authenticated | 用户登录后可访问
	 */
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		log.info("初始化安全配置...");
		return httpSecurity
				// CSRF禁用，因为不使用session
				.csrf(csrf -> {
					csrf.disable();
					log.debug("CSRF保护已禁用");
				})
				// 禁用HTTP响应标头
				.headers((headersCustomizer) -> {
					headersCustomizer.cacheControl(cache -> cache.disable())
							.frameOptions(options -> options.sameOrigin());
					log.debug("HTTP响应头已配置");
				})
				// 认证失败处理类
				.exceptionHandling(exception -> {
					exception.authenticationEntryPoint(unauthorizedHandler);
					log.debug("认证失败处理器已配置");
				})
				// 基于token，所以不需要session
				.sessionManagement(session -> {
					session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
					log.debug("会话管理已配置为无状态");
				}).authorizeHttpRequests((requests) -> {
					log.info("配置请求授权规则...");

					// 1. 硬编码允许匿名访问的路径
					requests.requestMatchers(new AntPathRequestMatcher("/login"),
							new AntPathRequestMatcher("/register"), new AntPathRequestMatcher("/captchaImage"),
							new AntPathRequestMatcher("/swagger-ui/**"), new AntPathRequestMatcher("/v3/api-docs/**"),
							new AntPathRequestMatcher("/webjars/**"), new AntPathRequestMatcher("/druid/**"),
							new AntPathRequestMatcher("/error")).permitAll();
					log.debug("已配置基础匿名访问路径");

					// 2. 静态资源允许匿名访问
					requests.requestMatchers(HttpMethod.GET, "/",
//							"/*.html",
//							"/**/*.html",
//							"/**/*.css",
//							"/**/*.js",
							"/profile/**").permitAll();
					log.debug("已配置静态资源访问规则");

					// 3. 动态加载的URL（添加路径校验）
					permitAllUrl.getUrls().forEach(url -> {
						if (url != null && !url.contains("/**/") && !url.contains("{*")) {
							try {
								AntPathRequestMatcher matcher = new AntPathRequestMatcher(url);
								log.debug("允许匿名访问路径: {}", url);
								requests.requestMatchers(matcher).permitAll();
							} catch (Exception e) {
								log.warn("跳过非法路径模式: {}, 原因: {}", url, e.getMessage());
							}
						} else {
							log.warn("跳过非法路径模式: {}", url);
						}
					});

					// 4. 其他所有请求需要认证
					requests.anyRequest().authenticated();
					log.info("请求授权规则配置完成");
				})
				// 添加Logout filter
				.logout(logout -> {
					logout.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
					log.debug("登出处理器已配置");
				})
				// 添加JWT filter
				.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
				// 添加CORS filter
				.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class)
				.addFilterBefore(corsFilter, LogoutFilter.class).build();
	}

	/**
	 * 强散列哈希加密实现
	 */
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		log.debug("初始化密码编码器");
		return new BCryptPasswordEncoder();
	}
}
