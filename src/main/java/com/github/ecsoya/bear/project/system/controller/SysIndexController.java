package com.github.ecsoya.bear.project.system.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.ecsoya.bear.common.utils.StringUtils;
import com.github.ecsoya.bear.framework.config.GlobalConfig;

/**
 * 首页
 *
 * @author bearfast_ry
 */
@RestController
public class SysIndexController {
	/** 系统基础配置 */
	@Autowired
	private GlobalConfig ruoyiConfig;

	/**
	 * 访问首页，提示语
	 */
	@RequestMapping("/")
	public String index() {
		return StringUtils.format("欢迎使用{}后台管理框架，当前版本：v{}，请通过前端地址访问。", ruoyiConfig.getName(), ruoyiConfig.getVersion());
	}
}
