package com.github.ecsoya.bear.common.xss;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import com.github.ecsoya.bear.common.utils.StringUtils;

/**
 * 自定义xss校验注解实现
 * 
 * @author bearfast_ry
 */
public class XssValidator implements ConstraintValidator<Xss, String> {
	private static final String HTML_PATTERN = "<(\\S*?)[^>]*>.*?|<.*? />";

	@Override
	public boolean isValid(String value, ConstraintValidatorContext constraintValidatorContext) {
		if (StringUtils.isBlank(value)) {
			return true;
		}
		return !containsHtml(value);
	}

	public static boolean containsHtml(String value) {
		StringBuilder sHtml = new StringBuilder();
		Pattern pattern = Pattern.compile(HTML_PATTERN);
		Matcher matcher = pattern.matcher(value);
		while (matcher.find()) {
			sHtml.append(matcher.group());
		}
		return pattern.matcher(sHtml).matches();
	}
}