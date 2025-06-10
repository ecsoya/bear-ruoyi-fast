package com.github.ecsoya.bear.framework.security.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.github.ecsoya.bear.common.constant.CacheConstants;
import com.github.ecsoya.bear.common.constant.Constants;
import com.github.ecsoya.bear.common.utils.ServletUtils;
import com.github.ecsoya.bear.common.utils.StringUtils;
import com.github.ecsoya.bear.common.utils.ip.AddressUtils;
import com.github.ecsoya.bear.common.utils.ip.IpUtils;
import com.github.ecsoya.bear.common.utils.uuid.IdUtils;
import com.github.ecsoya.bear.framework.redis.RedisCache;
import com.github.ecsoya.bear.framework.security.LoginUser;

import eu.bitwalker.useragentutils.UserAgent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;

/**
 * token验证处理
 * 
 * @author bearfast_ry
 */
@Component
public class TokenService {
	private static final Logger log = LoggerFactory.getLogger(TokenService.class);

	// 令牌自定义标识
	@Value("${token.header}")
	private String header;

	// 令牌密钥
	@Value("${token.secret}")
	private String secret;

	// 令牌有效期（默认30分钟）
	@Value("${token.expireTime}")
	private int expireTime;

	// 用于签名的密钥
	private byte[] signingKey;

	protected static final long MILLIS_SECOND = 1000;

	protected static final long MILLIS_MINUTE = 60 * MILLIS_SECOND;

	private static final Long MILLIS_MINUTE_TWENTY = 20 * 60 * 1000L;

	@Autowired
	private RedisCache redisCache;

	@PostConstruct
	public void init() {
		log.info("Token expireTime配置为: {} 分钟", expireTime);
		// 初始化安全的签名密钥
		if (StringUtils.isNotEmpty(secret) && secret.length() >= 64) {
			// 如果配置的密钥长度足够，直接使用配置的密钥
			signingKey = secret.getBytes();
			log.info("使用配置的密钥，长度: {} 位", signingKey.length * 8);
		} else {
			// 否则生成安全的随机密钥
			signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded();
			log.info("生成随机密钥，长度: {} 位", signingKey.length * 8);
			log.warn("注意：使用随机密钥会导致服务重启后之前的token失效，建议在配置中设置长度>=64的固定密钥");
			// 输出一个可用于配置的安全密钥
			String secureKeyBase64 = generateSecureKeyBase64();
			log.info("可用于配置的安全密钥(Base64编码): {}", secureKeyBase64);
		}

		testTokenExpireTime();
	}

	/**
	 * 获取用户身份信息
	 * 
	 * @return 用户信息
	 */
	public LoginUser getLoginUser(HttpServletRequest request) {
		// 获取请求携带的令牌
		String token = getToken(request);
		if (StringUtils.isNotEmpty(token)) {
			try {
				Claims claims = parseToken(token);
				// 先验证token是否过期
				Date expiration = claims.getExpiration();
				if (expiration != null && expiration.before(new Date())) {
					log.warn("Token已过期: {}", token);
					return null;
				}

				// 解析对应的权限以及用户信息
				String uuid = claims.get(Constants.LOGIN_USER_KEY, String.class);
				String userKey = getTokenKey(uuid);
				LoginUser user = redisCache.getCacheObject(userKey);

				if (user != null) {
					return user;
				} else {
					log.warn("Token有效但Redis中找不到用户信息: {}", token);
				}
			} catch (Exception e) {
				log.error("获取用户信息异常: {}", e.getMessage());
			}
		}
		return null;
	}

	/**
	 * 设置用户身份信息
	 */
	public void setLoginUser(LoginUser loginUser) {
		if (StringUtils.isNotNull(loginUser) && StringUtils.isNotEmpty(loginUser.getToken())) {
			refreshToken(loginUser);
		}
	}

	/**
	 * 删除用户身份信息
	 */
	public void delLoginUser(String token) {
		if (StringUtils.isNotEmpty(token)) {
			try {
				Claims claims = parseToken(token);
				String uuid = claims.get(Constants.LOGIN_USER_KEY, String.class);
				if (uuid != null) {
					String userKey = getTokenKey(uuid);
					redisCache.deleteObject(userKey);
				}
			} catch (Exception e) {
				log.error("删除用户信息异常: {}", e.getMessage());
			}
		}
	}

	public String getTokenByUserId(Long userId) {
		if (userId == null) {
			return null;
		}
		String key = getUserIdKey(userId);
		return redisCache.getCacheObject(key);
	}

	private String getUserIdKey(Long userId) {
		return String.format("login_user_id_token:%s", userId);
	}

	public void bindToken(Long userId, String token) {
		String key = getUserIdKey(userId);
		redisCache.setCacheObject(key, token, expireTime, TimeUnit.MINUTES);
	}

	/**
	 * 创建令牌
	 * 
	 * @param loginUser 用户信息
	 * @return 令牌
	 */
	public String createToken(LoginUser loginUser) {
		String token = IdUtils.fastUUID();
		loginUser.setToken(token);
		setUserAgent(loginUser);
		refreshToken(loginUser);

		Map<String, Object> claims = new HashMap<>();
		claims.put(Constants.LOGIN_USER_KEY, token);
		claims.put(Constants.JWT_USERNAME, loginUser.getUsername());
		claims.put(Constants.JWT_USERID, loginUser.getUserId());

		String jwtToken = Jwts.builder().setClaims(claims).setSubject(loginUser.getUsername()).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expireTime * MILLIS_MINUTE))
				.signWith(Keys.hmacShaKeyFor(signingKey)).compact();

		log.info("创建JWT令牌成功，有效期: {} 分钟", expireTime);
		return jwtToken;
	}

	/**
	 * 验证令牌有效期，相差不足20分钟，自动刷新缓存
	 * 
	 * @param loginUser 登录信息
	 * @return 令牌
	 */
	public void verifyToken(LoginUser loginUser) {
		long expireTime = loginUser.getExpireTime();
		long currentTime = System.currentTimeMillis();
		if (expireTime - currentTime <= MILLIS_MINUTE_TWENTY) {
			refreshToken(loginUser);
		}
	}

	/**
	 * 刷新令牌有效期
	 * 
	 * @param loginUser 登录信息
	 */
	public void refreshToken(LoginUser loginUser) {
		loginUser.setLoginTime(System.currentTimeMillis());
		long newExpireTime = loginUser.getLoginTime() + expireTime * MILLIS_MINUTE;
		loginUser.setExpireTime(newExpireTime);

		log.info("刷新令牌，登录时间: {}，过期时间: {}，有效期: {} 分钟", new Date(loginUser.getLoginTime()), new Date(newExpireTime),
				expireTime);

		// 根据uuid将loginUser缓存
		String userKey = getTokenKey(loginUser.getToken());
		redisCache.setCacheObject(userKey, loginUser, expireTime, TimeUnit.MINUTES);
		log.info("已设置Redis缓存过期时间为 {} 分钟", expireTime);
	}

	/**
	 * 设置用户代理信息
	 * 
	 * @param loginUser 登录信息
	 */
	public void setUserAgent(LoginUser loginUser) {
		UserAgent userAgent = UserAgent.parseUserAgentString(ServletUtils.getRequest().getHeader("User-Agent"));
		String ip = IpUtils.getIpAddr();
		loginUser.setIpaddr(ip);
		loginUser.setLoginLocation(AddressUtils.getRealAddressByIP(ip));
		loginUser.setBrowser(userAgent.getBrowser().getName());
		loginUser.setOs(userAgent.getOperatingSystem().getName());
	}

	/**
	 * 从令牌中获取用户名
	 *
	 * @param token 令牌
	 * @return 用户名
	 */
	public String getUsernameFromToken(String token) {
		try {
			Claims claims = parseToken(token);
			return claims.getSubject();
		} catch (Exception e) {
			log.error("从令牌中获取用户名异常: {}", e.getMessage());
			return null;
		}
	}

	/**
	 * 解析令牌
	 */
	private Claims parseToken(String token) {
		return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(signingKey)).build().parseClaimsJws(token)
				.getBody();
	}

	/**
	 * 获取请求token
	 *
	 * @param request
	 * @return token
	 */
	private String getToken(HttpServletRequest request) {
		String token = request.getHeader(header);
		if (StringUtils.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
			token = token.replace(Constants.TOKEN_PREFIX, "");
		}
		return token;
	}

	private String getTokenKey(String uuid) {
		return CacheConstants.LOGIN_TOKEN_KEY + uuid;
	}

	/**
	 * 测试令牌有效期配置 这个方法可以在系统启动时或者通过接口调用来检查令牌有效期配置是否正确
	 */
	public void testTokenExpireTime() {
		log.info("===== 令牌有效期配置测试 =====");
		log.info("配置的令牌有效期: {} 分钟", expireTime);
		log.info("计算后的过期毫秒数: {} 毫秒", expireTime * MILLIS_MINUTE);

		Date now = new Date();
		Date future = new Date(now.getTime() + expireTime * MILLIS_MINUTE);
		log.info("当前时间: {}", now);
		log.info("计算的过期时间: {}", future);
		log.info("时间差(毫秒): {}", future.getTime() - now.getTime());
		log.info("时间差(分钟): {}", (future.getTime() - now.getTime()) / MILLIS_MINUTE);
		log.info("===== 令牌有效期配置测试结束 =====");
	}

	/**
	 * 获取配置的令牌有效期（分钟）
	 */
	public int getExpireTime() {
		return expireTime;
	}

	/**
	 * 获取令牌自定义标识
	 */
	public String getHeader() {
		return header;
	}

	/**
	 * 验证Token的有效性
	 * 
	 * @param token JWT令牌
	 * @return 是否有效
	 */
	public boolean validateToken(String token) {
		if (StringUtils.isEmpty(token)) {
			log.warn("Token为空");
			return false;
		}

		try {
			log.info("开始验证Token: {}", token);
			Claims claims = parseToken(token);
			log.info("Token解析成功，包含的声明: {}", claims);

			Date expiration = claims.getExpiration();
			Date now = new Date();
			log.info("Token过期时间: {}, 当前时间: {}", expiration, now);

			boolean isValid = !expiration.before(now);
			log.info("Token是否有效: {}", isValid);

			if (isValid) {
				String uuid = claims.get(Constants.LOGIN_USER_KEY, String.class);
				String userKey = getTokenKey(uuid);
				LoginUser user = redisCache.getCacheObject(userKey);
				log.info("Redis中用户信息: {}", user != null ? user.getUsername() : "未找到");
			}

			return isValid;
		} catch (Exception e) {
			log.error("验证Token时发生异常: {}", e.getMessage(), e);
			return false;
		}
	}

	/**
	 * 生成安全的HS512密钥
	 * @return 生成的安全密钥的Base64编码
	 */
	public String generateSecureKeyBase64() {
		byte[] key = Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded();
		String base64Key = java.util.Base64.getEncoder().encodeToString(key);
		log.info("生成安全密钥，长度：{} 位", key.length * 8);
		return base64Key;
	}
}
