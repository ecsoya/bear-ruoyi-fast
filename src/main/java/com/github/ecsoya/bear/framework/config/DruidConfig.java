package com.github.ecsoya.bear.framework.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.spring.boot.autoconfigure.DruidDataSourceBuilder;
import com.alibaba.druid.util.Utils;
import com.github.ecsoya.bear.common.utils.spring.SpringUtils;
import com.github.ecsoya.bear.framework.aspectj.lang.enums.DataSourceType;
import com.github.ecsoya.bear.framework.config.properties.DruidProperties;
import com.github.ecsoya.bear.framework.datasource.DynamicDataSource;

/**
 * druid 配置多数据源
 * 
 * @author bearfast_ry
 */
@Configuration
public class DruidConfig {
	@Bean
	@ConfigurationProperties("spring.datasource.druid.master")
	public DataSource masterDataSource(DruidProperties druidProperties) {
		DruidDataSource dataSource = DruidDataSourceBuilder.create().build();
		return druidProperties.dataSource(dataSource);
	}

	@Bean
	@ConfigurationProperties("spring.datasource.druid.slave")
	@ConditionalOnProperty(prefix = "spring.datasource.druid.slave", name = "enabled", havingValue = "true")
	public DataSource slaveDataSource(DruidProperties druidProperties) {
		DruidDataSource dataSource = DruidDataSourceBuilder.create().build();
		return druidProperties.dataSource(dataSource);
	}

	@Bean(name = "dynamicDataSource")
	@Primary
	public DynamicDataSource dataSource(DataSource masterDataSource) {
		Map<Object, Object> targetDataSources = new HashMap<>();
		targetDataSources.put(DataSourceType.MASTER.name(), masterDataSource);
		setDataSource(targetDataSources, DataSourceType.SLAVE.name(), "slaveDataSource");
		return new DynamicDataSource(masterDataSource, targetDataSources);
	}

	/**
	 * 设置数据源
	 * 
	 * @param targetDataSources 备选数据源集合
	 * @param sourceName        数据源名称
	 * @param beanName          bean名称
	 */
	public void setDataSource(Map<Object, Object> targetDataSources, String sourceName, String beanName) {
		try {
			DataSource dataSource = SpringUtils.getBean(beanName);
			targetDataSources.put(sourceName, dataSource);
		} catch (Exception e) {
		}
	}

	/**
	 * 去除监控页面底部的广告
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Bean
	@ConditionalOnProperty(name = "spring.datasource.druid.stat-view-servlet.enabled", havingValue = "true")
	public FilterRegistrationBean removeDruidFilterRegistrationBean() {
		// 创建filter进行过滤
		Filter filter = new Filter() {
			@Override
			public void init(jakarta.servlet.FilterConfig filterConfig) throws ServletException {
			}

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				chain.doFilter(request, response);
				// 重置缓冲区，响应头不会被重置
				response.resetBuffer();
				// 获取common.js
				String text = Utils.readFromResource("support/http/resources/js/common.js");
				// 正则替换banner, 除去底部的广告信息
				text = text.replaceAll("<a.*?banner\"></a><br/>", "");
				text = text.replaceAll("powered.*?shrek.wang</a>", "");
				response.getWriter().write(text);
			}

			@Override
			public void destroy() {
			}
		};
		FilterRegistrationBean registrationBean = new FilterRegistrationBean();
		registrationBean.setFilter(filter);
		registrationBean.addUrlPatterns("/druid/js/common.js");
		return registrationBean;
	}
}
