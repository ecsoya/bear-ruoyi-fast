package com.github.ecsoya.bear.framework.aspectj.lang.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.ecsoya.bear.framework.aspectj.lang.enums.DesensitizedType;
import com.github.ecsoya.bear.framework.config.SensitiveJsonSerializer;

/**
 * 数据脱敏注解
 *
 * @author bearfast_ry
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@JacksonAnnotationsInside
@JsonSerialize(using = SensitiveJsonSerializer.class)
public @interface Sensitive {
	DesensitizedType desensitizedType();
}
