package com.github.ecsoya.bear.framework.security.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import eu.bitwalker.useragentutils.UserAgent;
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

	protected static final long MILLIS_SECOND = 1000;

	protected static final long MILLIS_MINUTE = 60 * MILLIS_SECOND;

	private static final Long MILLIS_MINUTE_TWENTY = 20 * 60 * 1000L;

	@Autowired
	private RedisCache redisCache;

	private final JwtEncoder jwtEncoder;
	private final JwtDecoder jwtDecoder;

	public TokenService() {
		// 生成RSA密钥对
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		// 创建JWK
		JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
		JWKSet jwkSet = new JWKSet(jwk);
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

		// 创建JWT编码器和解码器
		this.jwtEncoder = new NimbusJwtEncoder(jwkSource);
		this.jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
	}

	private KeyPair generateRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException("Error generating RSA key pair", ex);
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
				Jwt jwt = jwtDecoder.decode(token);
				// 解析对应的权限以及用户信息
				String uuid = jwt.getClaimAsString(Constants.LOGIN_USER_KEY);
				String userKey = getTokenKey(uuid);
				LoginUser user = redisCache.getCacheObject(userKey);
				if (user != null) {
					// 验证token是否过期
					Instant expiresAt = jwt.getExpiresAt();
					if (expiresAt != null && expiresAt.isBefore(Instant.now())) {
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
				Jwt jwt = jwtDecoder.decode(token);
				String uuid = jwt.getClaimAsString(Constants.LOGIN_USER_KEY);
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

		Instant now = Instant.now();
		Instant expiryDate = now.plus(expireTime, ChronoUnit.MINUTES);

		Map<String, Object> claims = new HashMap<>();
		claims.put(Constants.LOGIN_USER_KEY, token);
		claims.put(Constants.JWT_USERNAME, loginUser.getUsername());
		claims.put(Constants.JWT_USERID, loginUser.getUserId());

		JwtClaimsSet claimsSet = JwtClaimsSet.builder().subject(loginUser.getUsername()).claims(c -> c.putAll(claims))
				.issuedAt(now).expiresAt(expiryDate).build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
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
			Jwt jwt = jwtDecoder.decode(token);
			return jwt.getSubject();
		} catch (Exception e) {
			log.error("从令牌中获取用户名异常: {}", e.getMessage());
			return null;
		}
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
