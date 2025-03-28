package ysm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest"
)

type UserIdKey struct{}

type JwtConfig struct {
	AccessExpire          int    // token过期时间（秒）
	AccessTokenSecret     string // At密钥
	AccessRefreshDeadLine int    // token截止刷新时间（秒）
	RefreshExpire         int    // token刷新时间（秒）
	RefreshTimeLimit      int    // token限制刷新时间间隔（秒）
	RefreshTokenSecret    string // Rt密钥
	Issuer                string // token签发者
}

type CorsConfig struct {
	AllowedOrigins []string
	AllowHeaders   []string
	ExposeHeaders  []string
}

// JwtAuthMiddleware 创建并返回 JWT 认证中间件
// Header:nil; "new_access_token", newAccessToken;"refresh_at_fail", err.Error()
func JwtAuthMiddleware(cfg JwtConfig, redis *redis.Redis, excludedPaths []string) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			// w.Header().Set("Access-Control-Allow-Headers", "refresh-token")
			// w.Header().Set("Access-Control-Expose-Headers", "new_access_token")

			// 检查当前路径是否在排除列表中
			for _, path := range excludedPaths {
				if r.URL.Path == path {
					next(w, r)
					return
				}
			}

			var claims *Claims
			var err error

			// 获取 Authorization 头
			authHeader := r.Header.Get("Authorization")
			var tokenString string
			if authHeader != "" {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}

			// 如果存在 accessToken，尝试解析
			// if tokenString != "" {
			// 校验accessToken
			claims, err = VaildateAccessToken(tokenString, cfg.AccessTokenSecret, redis)
			// 如果 accessToken 无效，尝使用 refreshToken 生成有效的 accessToken
			if err != nil || claims == nil {
				newAccessToken, refreshClaims, refreshErr := RefreshAccessToken(
					r, cfg, tokenString, cfg.AccessTokenSecret, redis,
				)
				// 如果accessToken与refreshToken 均无效，则返回二者的错误信息
				if refreshErr != nil || refreshClaims == nil {
					http.Error(w, "Valid At err:"+err.Error()+", Valid Rt err:"+refreshErr.Error(), http.StatusUnauthorized)
					return
				}
				// accessToken 无效时, refreshToken 有效, 设置新生成的 access token 到响应头
				w.Header().Set("new_access_token", newAccessToken)
				http.Error(w, "invalid or overdue access token", http.StatusUnauthorized)
				return
			} else {
				// 判断 accessToken 是否接近过期
				now := time.Now().Unix()
				if claims.ExpiresAt.Unix()-now >= int64(cfg.AccessRefreshDeadLine) {
					// 如果 access token 还有足够的时间，则直接继续处理请求
					ctx := context.WithValue(r.Context(), UserIdKey{}, claims.UserID)
					next(w, r.WithContext(ctx))
					return
				}
			}

			newAccessToken, refreshClaims, err := RefreshAccessToken(
				r, cfg, tokenString, cfg.AccessTokenSecret, redis,
			)

			if err != nil || refreshClaims == nil {
				w.Header().Set("refresh_at_fail", err.Error())
				ctx := context.WithValue(r.Context(), UserIdKey{}, claims.UserID)
				next(w, r.WithContext(ctx))
				return
			}

			// 设置新生成的 access token 到响应头
			w.Header().Set("new_access_token", newAccessToken)

			// 使用刷新后的用户信息更新上下文
			ctx := context.WithValue(r.Context(), UserIdKey{}, refreshClaims.UserID)
			next(w, r.WithContext(ctx))
			// } else {
			// 	// 如果不存在 accessToken，则直接返回
			// 	http.Error(w, "no access token", http.StatusUnauthorized)
			// 	return
			// }

		}
	}
}

func RefreshAccessToken(r *http.Request, cfg JwtConfig, accessToken string, secret string, redis *redis.Redis) (string, *Claims, error) {
	// 尝试使用 refresh token 更新 access token
	refreshTokenString := r.Header.Get("Refresh-Token")
	if refreshTokenString == "" {
		return "", nil, errors.New("access token is missing or invalid and refresh token is required for renewing access token")
	}

	// 验证 refresh token
	refreshClaims, err := ValidateRefreshToken(refreshTokenString, cfg.RefreshTokenSecret, redis)
	if err != nil || refreshClaims == nil {
		return "", nil, fmt.Errorf("failed to validate refresh token: %v", err)
	}

	// 删除旧的 access token
	if exists, _ := redis.Exists(fmt.Sprintf("%s:%s", "accessToken", accessToken)); exists {
		redis.Del(fmt.Sprintf("%s:%s", "accessToken", accessToken))
	}

	// 当配置了间隔时间大于0时，则设置时间限制刷新点, 此点存在期间内不再生成新的 access token
	if cfg.RefreshTimeLimit > 0 {
		// 设置时间限制刷新点, 此点存在期间内不再生成新的 access token
		if exists, _ := redis.Exists("tokenRefreshTimeLimit:" + refreshTokenString); exists {
			return "", nil, fmt.Errorf(
				"please wait for %d seconds before refreshing the token again",
				cfg.RefreshTimeLimit,
			)
		} else {
			// 基于配置文件的时间限制(int)生成对应限制时间的限制点
			if err := redis.Setex("tokenRefreshTimeLimit:"+refreshTokenString,
				fmt.Sprintf("refresh token time limit by this data: %d (s)", cfg.RefreshTimeLimit),
				cfg.RefreshTimeLimit,
			); err != nil {
				return "", nil, fmt.Errorf("can not set the refresh time limit: %v", err)
			}
		}
	}

	// 生成新的 access token 并设置其有效期为 AccessExpire
	newAccessToken, err := GenerateAccessToken(redis, refreshClaims.UserID, cfg)
	if err != nil {
		return "", nil, err
	}

	return newAccessToken, refreshClaims, nil
}

// Claims represents what we want to put in the token
type Claims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}

// 获取token，若已存在则不再额外生成token
func GetOrCreateToken(tokenType string, redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error) {
	var expire int
	var secret string
	if tokenType == "accessToken" {
		expire = jwtConfig.AccessExpire
		secret = jwtConfig.AccessTokenSecret
	} else if tokenType == "refreshToken" {
		expire = jwtConfig.RefreshExpire
		secret = jwtConfig.RefreshTokenSecret
	} else {
		return "", fmt.Errorf("invalid token type")
	}

	// 生成新的 JWT token
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtConfig.Issuer, // Replace with your service name
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(expire))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to generate %s: %v", tokenType, err)
	}

	// 存储新的 token 到 Redis
	if err := WriteTokenToRedis(redis, tokenType+":", newToken, userID, expire); err != nil {
		return "", fmt.Errorf("failed to write %s to redis: %v", tokenType, err)
	}

	return newToken, nil
}

// GenerateAccessToken generates an access token with a specified expiration time.
func GenerateAccessToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error) {
	return GetOrCreateToken("accessToken", redis, userID, jwtConfig)
}

// GenerateRefreshToken generates a refresh token with a specified expiration time.
func GenerateRefreshToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error) {
	return GetOrCreateToken("refreshToken", redis, userID, jwtConfig)
}

func WriteTokenToRedis(redis *redis.Redis, key string, token string, userID int64, duration int) error {
	if err := redis.Setex(key+token, strconv.FormatInt(userID, 10), duration); err != nil {
		return fmt.Errorf("failed to write token to redis: %v", err)
	}
	return nil
}

func VaildateAccessToken(tokenStr string, secret string, redis *redis.Redis) (*Claims, error) {
	return parseToken("accessToken", tokenStr, secret, redis)
}

func ValidateRefreshToken(tokenStr string, secret string, redis *redis.Redis) (*Claims, error) {
	return parseToken("refreshToken", tokenStr, secret, redis)
}

func parseToken(tokenType string, tokenStr string, secret string, redis *redis.Redis) (*Claims, error) {
	// 解析 token
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	// 校验 token 合法性
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// 检查 token 是否在 Redis 中并且值是否匹配
		exists, err := redis.Exists(fmt.Sprintf("%s:%s", tokenType, tokenStr))
		if err != nil {
			return nil, fmt.Errorf("error checking token in redis: %v", err)
		}
		// 如果从key获取的token在redis中，则返回claims
		if exists {
			return claims, nil
		} else {
			return nil, fmt.Errorf("sent token does not match the token in redis")
		}
	}

	return nil, fmt.Errorf("invalid %s", tokenType)
}
