package com.github.ecsoya.bear.framework.security.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

	// 令牌有效期（默认30分钟）
	@Value("${token.expireTime}")
	private int expireTime;

	// 令牌密钥
	@Value("${token.secret}")
	private String secret;

	protected static final long MILLIS_SECOND = 1000;

	protected static final long MILLIS_MINUTE = 60 * MILLIS_SECOND;

	private static final Long MILLIS_MINUTE_TWENTY = 20 * 60 * 1000L;

	@Autowired
	private RedisCache redisCache;

	private byte[] keyBytes;

	@PostConstruct
	public void initJwtCodec() {
		// 确保密钥长度至少为256位（32字节）
		byte[] secretBytes = secret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		if (secretBytes.length < 32) {
			keyBytes = new byte[32];
			System.arraycopy(secretBytes, 0, keyBytes, 0, Math.min(secretBytes.length, 32));
		} else {
			keyBytes = secretBytes;
		}
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
				// 解析对应的权限以及用户信息
				String uuid = claims.get(Constants.LOGIN_USER_KEY, String.class);
				String userKey = getTokenKey(uuid);
				LoginUser user = redisCache.getCacheObject(userKey);
				if (user != null) {
					// 验证token是否过期
					Date expiration = claims.getExpiration();
					if (expiration != null && expiration.before(new Date())) {
						log.warn("Token已过期: {}", token);
						return null;
					}
					return user;
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

		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + expireTime * MILLIS_MINUTE);

		Map<String, Object> claims = new HashMap<>();
		claims.put(Constants.LOGIN_USER_KEY, token);
		claims.put(Constants.JWT_USERNAME, loginUser.getUsername());
		claims.put(Constants.JWT_USERID, loginUser.getUserId());

		return Jwts.builder()
				.setClaims(claims)
				.setSubject(loginUser.getUsername())
				.setIssuedAt(now)
				.setExpiration(expiryDate)
				.signWith(Keys.hmacShaKeyFor(keyBytes), SignatureAlgorithm.HS256)
				.compact();
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
	 * 刷新令牌有效期
	 * 
	 * @param loginUser 登录信息
	 */
	public void refreshToken(LoginUser loginUser) {
		loginUser.setLoginTime(System.currentTimeMillis());
		loginUser.setExpireTime(loginUser.getLoginTime() + expireTime * MILLIS_MINUTE);
		// 根据uuid将loginUser缓存
		String userKey = getTokenKey(loginUser.getToken());
		redisCache.setCacheObject(userKey, loginUser, expireTime, TimeUnit.MINUTES);
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
		return Jwts.parserBuilder()
				.setSigningKey(Keys.hmacShaKeyFor(keyBytes))
				.build()
				.parseClaimsJws(token)
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
}
