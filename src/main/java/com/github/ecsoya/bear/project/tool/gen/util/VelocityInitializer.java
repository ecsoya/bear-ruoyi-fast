package com.github.ecsoya.bear.project.tool.gen.util;

import java.util.Properties;

import org.apache.velocity.app.Velocity;

import com.github.ecsoya.bear.common.constant.Constants;

/**
 * VelocityEngine工厂
 * 
 * @author bearfast_ry
 */
public class VelocityInitializer {
	/**
	 * 初始化vm方法
	 */
	public static void initVelocity() {
		Properties p = new Properties();
		try {
			// 加载classpath目录下的vm文件
			p.setProperty("resource.loader.file.class",
					"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
			// 定义字符集
			p.setProperty(Velocity.INPUT_ENCODING, Constants.UTF8);
			// 初始化Velocity引擎，指定配置Properties
			Velocity.init(p);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
