package com.github.ecsoya.bear.project.system.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.github.ecsoya.bear.common.utils.StringUtils;
import com.github.ecsoya.bear.framework.aspectj.lang.annotation.Anonymous;
import com.github.ecsoya.bear.framework.security.RegisterBody;
import com.github.ecsoya.bear.framework.security.service.SysRegisterService;
import com.github.ecsoya.bear.framework.web.controller.BaseController;
import com.github.ecsoya.bear.framework.web.domain.AjaxResult;
import com.github.ecsoya.bear.project.system.service.ISysConfigService;

/**
 * 注册验证
 * 
 * @author bearfast_ry
 */
@RestController
public class SysRegisterController extends BaseController {
	@Autowired
	private SysRegisterService registerService;

	@Autowired
	private ISysConfigService configService;

	@Anonymous
	@PostMapping("/register")
	public AjaxResult register(@RequestBody RegisterBody user) {
		if (!("true".equals(configService.selectConfigByKey("sys.account.registerUser")))) {
			return error("当前系统没有开启注册功能！");
		}
		String msg = registerService.register(user);
		return StringUtils.isEmpty(msg) ? success() : error(msg);
	}
}
