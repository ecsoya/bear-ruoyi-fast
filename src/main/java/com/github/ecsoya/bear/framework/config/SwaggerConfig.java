package com.github.ecsoya.bear.framework.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

/**
 * Swagger3的接口配置
 * 
 * @author bearfast_ry
 */
@Configuration
public class SwaggerConfig {
	/** 系统基础配置 */
	@Autowired
	private GlobalConfig ruoyiConfig;

	/** 是否开启swagger */
	@Value("${swagger.enabled}")
	private boolean enabled;

	/** 设置请求的统一前缀 */
	@Value("${swagger.pathMapping}")
	private String pathMapping;

	@Bean
	public OpenAPI openAPI() {
		return new OpenAPI()
				.info(new Info()
						.title("标题：若依管理系统_接口文档")
						.description("描述：用于管理集团旗下公司的人员信息,具体包括XXX,XXX模块...")
						.version("版本号:" + ruoyiConfig.getVersion())
						.contact(new Contact()
								.name(ruoyiConfig.getName())))
				.addSecurityItem(new SecurityRequirement().addList("Authorization"))
				.components(new Components()
						.addSecuritySchemes("Authorization",
								new SecurityScheme()
										.type(SecurityScheme.Type.HTTP)
										.scheme("bearer")
										.bearerFormat("JWT")
										.in(SecurityScheme.In.HEADER)
										.name("Authorization")));
	}
}
