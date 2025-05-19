package com.github.ecsoya.bear.project.tool.swagger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * swagger 测试
 * 
 * @author bearfast_ry
 */
@Tag(name = "测试接口")
@RestController
@RequestMapping("/test")
public class TestController {
	private final static Map<Integer, UserEntity> users = new LinkedHashMap<Integer, UserEntity>();

	{
		users.put(1, new UserEntity(1, "admin", "admin123", "15888888888"));
		users.put(2, new UserEntity(2, "ry", "admin123", "15666666666"));
	}

	@Operation(summary = "获取用户列表")
	@GetMapping("/list")
	public List<UserEntity> userList() {
		List<UserEntity> userList = new ArrayList<UserEntity>(users.values());
		return userList;
	}

	@Operation(summary = "获取用户详细")
	@Parameter(name = "userId", description = "用户ID", required = true)
	@GetMapping("/{userId}")
	public UserEntity getUser(@PathVariable Integer userId) {
		return users.get(userId);
	}

	@Operation(summary = "新增用户")
	@Parameters({
		@Parameter(name = "userId", description = "用户ID", required = true),
		@Parameter(name = "username", description = "用户名称", required = true),
		@Parameter(name = "password", description = "用户密码", required = true),
		@Parameter(name = "mobile", description = "用户手机", required = true)
	})
	@PostMapping("/save")
	public String save(UserEntity user) {
		users.put(user.getUserId(), user);
		return "success";
	}

	@Operation(summary = "修改用户")
	@PutMapping("/update")
	public String update(@RequestBody UserEntity user) {
		users.put(user.getUserId(), user);
		return "success";
	}

	@Operation(summary = "删除用户")
	@Parameter(name = "userId", description = "用户ID", required = true)
	@DeleteMapping("/{userId}")
	public String delete(@PathVariable Integer userId) {
		users.remove(userId);
		return "success";
	}
}

@Schema(description = "用户实体")
class UserEntity {
	@Schema(description = "用户ID")
	private Integer userId;

	@Schema(description = "用户名称")
	private String username;

	@Schema(description = "用户密码")
	private String password;

	@Schema(description = "用户手机")
	private String mobile;

	public UserEntity() {

	}

	public UserEntity(Integer userId, String username, String password, String mobile) {
		this.userId = userId;
		this.username = username;
		this.password = password;
		this.mobile = mobile;
	}

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getMobile() {
		return mobile;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}
}
