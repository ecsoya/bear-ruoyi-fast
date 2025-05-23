package com.github.ecsoya.bear.common.exception.user;

/**
 * 用户不存在异常类
 * 
 * @author bearfast_ry
 */
public class UserNotExistsException extends UserException {
	private static final long serialVersionUID = 1L;

	public UserNotExistsException() {
		super("user.not.exists", null);
	}
}
