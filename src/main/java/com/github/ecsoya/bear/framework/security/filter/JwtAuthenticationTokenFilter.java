package com.github.ecsoya.bear.framework.security.filter;

import java.io.IOException;
import java.util.Date;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.ecsoya.bear.common.utils.SecurityUtils;
import com.github.ecsoya.bear.common.utils.StringUtils;
import com.github.ecsoya.bear.framework.security.LoginUser;
import com.github.ecsoya.bear.framework.security.service.TokenService;

/**
 * token过滤器 验证token有效性
 * 
 * @author bearfast_ry
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);

	@Autowired
	private TokenService tokenService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		try {
			log.debug("JWT过滤器开始处理请求: {}", request.getRequestURI());
			LoginUser loginUser = tokenService.getLoginUser(request);
			if (StringUtils.isNotNull(loginUser)) {
				log.debug("找到有效的登录用户: {}, 过期时间: {}", 
						loginUser.getUsername(), 
						new Date(loginUser.getExpireTime()));
						
				if (StringUtils.isNull(SecurityUtils.getAuthentication())) {
					tokenService.verifyToken(loginUser);
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser,
							null, loginUser.getAuthorities());
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					log.debug("用户 {} 已通过token认证并更新SecurityContext", loginUser.getUsername());
				} else {
					log.debug("用户 {} 已有认证信息，无需重新认证", loginUser.getUsername());
				}
			} else {
				log.debug("未找到有效的登录用户或token");
			}
		} catch (Exception e) {
			log.error("token认证失败: {}", e.getMessage());
		}
		chain.doFilter(request, response);
	}
}
