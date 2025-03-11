package ysm

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest"
)

type userIdKey struct{}

type JwtConfig struct {
	AccessExpire          int    // token过期时间（秒）
	AccessTokenSecret     string // At密钥
	AccessRefreshDeadLine int    // token截止刷新时间（秒）
	RefreshExpire         int    // token刷新时间（秒）
	RefreshTokenSecret    string // Rt密钥
	Issuer                string // token签发者
	// Secret             string // token加密密钥
}

// JwtAuthMiddleware 创建并返回 JWT 认证中间件
func JwtAuthMiddleware(cfg JwtConfig, redis *redis.Redis, excludedPaths []string) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
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
			if tokenString != "" {
				// claims, err = parseToken(tokenString, cfg.Secret)
				claims, err = VaildateAccessToken(tokenString, cfg.AccessTokenSecret, redis)
				if err != nil || claims == nil {
					http.Error(w, "invalid or overdue access token", http.StatusUnauthorized)
					return
				} else {
					// 判断 accessToken 是否接近过期
					now := time.Now().Unix()
					if claims.ExpiresAt.Unix()-now >= int64(cfg.AccessRefreshDeadLine) {
						// 如果 access token 还有足够的时间，则直接继续处理请求
						ctx := context.WithValue(r.Context(), userIdKey{}, claims.UserID)
						next(w, r.WithContext(ctx))
						return
					}
				}
			}

			// 尝试使用 refresh token 更新 access token
			refreshTokenString := r.Header.Get("Refresh-Token")
			if refreshTokenString == "" {
				http.Error(w, "access token is missing or invalid and refresh token is required for renewing access token", http.StatusUnauthorized)
				return
			}

			// 验证 refresh token
			// refreshClaims, err := parseToken(refreshTokenString, cfg.Secret)
			refreshClaims, err := ValidateRefreshToken(refreshTokenString, cfg.RefreshTokenSecret, redis)
			if err != nil || refreshClaims == nil {
				http.Error(w, "refresh token expired or invalid, please log in again", http.StatusUnauthorized)
				return
			}

			// 生成新的 access token 并设置其有效期为 AccessExpire
			newAccessToken, err := GenerateAccessToken(redis, refreshClaims.UserID, cfg)
			if err != nil {
				http.Error(w, "failed to generate new access token", http.StatusInternalServerError)
				return
			}

			// 设置新生成的 access token 到响应头
			w.Header().Set("New-Access-Token", newAccessToken)

			// 使用刷新后的用户信息更新上下文
			ctx := context.WithValue(r.Context(), userIdKey{}, refreshClaims.UserID)
			next(w, r.WithContext(ctx))
		}
	}
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

	// 构建用于查找已有 token 的 Redis 键名, 让refreshToken每人至多一个
	if tokenType == "refreshToken" {
		tokenKey := fmt.Sprintf("%s:%d", tokenType, userID)

		// 尝试从 Redis 获取现有的 token
		existingToken, err := redis.GetCtx(context.Background(), tokenKey)
		if err == nil && existingToken != "" {
			// 如果 Redis 中已有有效的 token，则直接返回
			return existingToken, nil
		}
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
	if err := WriteTokenToRedis(redis, tokenType+":", userID, newToken, expire); err != nil {
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

func WriteTokenToRedis(redis *redis.Redis, key string, userID int64, token string, duration int) error {
	if err := redis.Setex(key+strconv.FormatInt(userID, 10), token, duration); err != nil {
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
		storedToken, err := redis.GetCtx(context.Background(), fmt.Sprintf("%s:%d", tokenType, claims.UserID))
		if err != nil {
			return nil, fmt.Errorf("error checking token in redis: %v", err)
		}
		// 如果从key获取的token在redis中，则返回claims
		if storedToken == tokenStr {
			return claims, nil
		} else {
			return nil, fmt.Errorf("sent token does not match the token in redis")
		}
	}

	return nil, fmt.Errorf("invalid token")
}
