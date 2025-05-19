package com.github.ecsoya.bear.framework.config.properties;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang3.RegExUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.github.ecsoya.bear.framework.aspectj.lang.annotation.Anonymous;

/**
 * 设置Anonymous注解允许匿名访问的url
 * 
 * @author bearfast_ry
 */
@Configuration
public class PermitAllUrlProperties implements InitializingBean, ApplicationContextAware {
	private static final Logger log = LoggerFactory.getLogger(PermitAllUrlProperties.class);
	private static final Pattern PATTERN = Pattern.compile("\\{(.*?)\\}");
	private static final String ASTERISK = "*";

	private ApplicationContext applicationContext;
	private final List<String> urls = new ArrayList<>();

	@Override
	public void afterPropertiesSet() {
		log.info("=== 开始收集匿名访问URL ===");
		try {
			RequestMappingHandlerMapping mapping = applicationContext.getBean(RequestMappingHandlerMapping.class);
			Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
			log.info("找到 {} 个处理器方法", map.size());

			map.keySet().forEach(info -> {
				HandlerMethod handlerMethod = map.get(info);
				String methodName = handlerMethod.getMethod().getName();
				String className = handlerMethod.getBeanType().getSimpleName();
				log.debug("检查方法: {}.{}", className, methodName);

				Anonymous method = AnnotationUtils.findAnnotation(handlerMethod.getMethod(), Anonymous.class);
				Anonymous controller = AnnotationUtils.findAnnotation(handlerMethod.getBeanType(), Anonymous.class);

				if (info.getPatternsCondition() != null && (method != null || controller != null)) {
					log.debug("发现 @Anonymous 注解: {}.{}", className, methodName);
					info.getPatternsCondition().getPatterns().forEach(url -> {
						try {
							log.debug("处理URL: {}", url);
							String normalizedUrl = normalizeUrl(url);
							log.debug("规范化后的URL: {}", normalizedUrl);

							if (isValidPath(normalizedUrl)) {
								urls.add(normalizedUrl);
								log.info("添加匿名访问路径: {}", normalizedUrl);
							} else {
								log.warn("跳过非法路径模式: {}", url);
							}
						} catch (Exception e) {
							log.error("处理URL时发生错误: {}, 原因: {}", url, e.getMessage(), e);
						}
					});
				}
			});

			log.info("=== 匿名访问URL收集完成 ===");
			log.info("共收集到 {} 个路径:", urls.size());
			urls.forEach(url -> log.info("- {}", url));

		} catch (Exception e) {
			log.error("收集匿名访问URL时发生错误", e);
		}
	}

	private String normalizeUrl(String url) {
		if (url == null || url.isEmpty()) {
			log.debug("URL为空，返回根路径");
			return "/";
		}

		log.debug("开始规范化URL: {}", url);

		// 替换路径变量为通配符
		String normalized = RegExUtils.replaceAll(url, PATTERN, ASTERISK);
		log.debug("替换路径变量后: {}", normalized);

		// 确保路径以 / 开头
		if (!normalized.startsWith("/")) {
			normalized = "/" + normalized;
			log.debug("添加前导斜杠后: {}", normalized);
		}

		// 移除多余的斜杠
		normalized = normalized.replaceAll("//+", "/");
		log.debug("移除多余斜杠后: {}", normalized);

		// 处理连续的星号
		normalized = normalized.replaceAll("\\*+", "*");
		log.debug("处理连续星号后: {}", normalized);

		// 确保路径不以 / 结尾（除非是根路径）
		if (normalized.length() > 1 && normalized.endsWith("/")) {
			normalized = normalized.substring(0, normalized.length() - 1);
			log.debug("移除尾部斜杠后: {}", normalized);
		}

		return normalized;
	}

	private boolean isValidPath(String path) {
		if (path == null || path.isEmpty()) {
			log.debug("路径为空，无效");
			return false;
		}

		try {
			log.debug("开始验证路径: {}", path);

			// 使用 AntPathRequestMatcher 验证路径
			AntPathRequestMatcher matcher = new AntPathRequestMatcher(path);
			String pattern = matcher.getPattern();
			log.debug("AntPathRequestMatcher模式: {}", pattern);

			// 检查路径是否包含非法模式
			if (pattern.contains("/**/") || pattern.contains("{*") || pattern.contains("**")) {
				log.debug("路径包含非法模式");
				return false;
			}

			// 检查路径变量格式
			if (pattern.contains("{") && !pattern.matches(".*\\{[a-zA-Z0-9_]+\\}.*")) {
				log.debug("路径变量格式不正确");
				return false;
			}

			log.debug("路径验证通过");
			return true;
		} catch (Exception e) {
			log.error("路径验证失败: {}, 原因: {}", path, e.getMessage(), e);
			return false;
		}
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.applicationContext = context;
	}

	public List<String> getUrls() {
		return urls;
	}
}
