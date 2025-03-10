# jwt_auth_middleware

自己写的依赖：[yuan-shuo/ysm: gozero custom middleware - gozero自定义中间件包](https://github.com/yuan-shuo/ysm?tab=Apache-2.0-1-ov-file)

使用双token（At + Rt）并可以配置多种参数

## 获取 / GET

```go
go get github.com/yuan-shuo/ysm@v1.0.0
```

## 功能函数 / Func

```go
// 1. JwtAuthMiddleware: 先看at，有，校验过就过，校验不过就返回错误。at没有/时间不足看rt，有就增加New-Access-Token响应头通知前端更新最新的access_token（时间刷新，字符串也可能刷新）
JwtAuthMiddleware(cfg JwtConfig, redis *redis.Redis, excludedPaths []string) rest.Middleware

// 2. GenerateAccessToken: 获取AccessToken并搭配Uid写入redis, jwtConfig包含其有效期
GenerateAccessToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error)

// 3. GenerateRefreshToken: 获取RefreshToken并搭配Uid写入redis, jwtConfig包含其有效期
GenerateRefreshToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error)
```

其中的自定义类型：

```go
// JwtConfig
type JwtConfig struct {
	AccessExpire          int    // token过期时间（秒）
	AccessRefreshDeadLine int    // token截止刷新时间（秒）
	RefreshExpire         int    // token刷新时间（秒）
	Secret                string // token加密密钥
	Issuer                string // token签发者
}
```

```go
// package redis ("github.com/zeromicro/go-zero/core/stores/redis")
// *redis.Redis
type Redis struct {
    Addr  string
    Type  string
    User  string
    Pass  string
    tls   bool
    brk   breaker.Breaker
    hooks []red.Hook
}
```

```go
// import "github.com/zeromicro/go-zero/rest"
// rest.Middleware
type Middleware func(next http.HandlerFunc) http.HandlerFunc
```

## 使用中间件 / How to use

### main

一行就行

```go
func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c)

	server := rest.MustNewServer(c.RestConf)
	defer server.Stop()

	ctx := svc.NewServiceContext(c)

	// 调用包, 直接完成 JWT + NoJwtUrl 校验中间件
	server.Use(ysm.JwtAuthMiddleware(c.JwtConfig, ctx.Redis, c.NoJwtUrl.Urls))

	handler.RegisterHandlers(server, ctx)

	fmt.Printf("Starting server at %s:%d...\n", c.Host, c.Port)
	server.Start()
}
```

### config

加两个：包自带的类型+一个string切片

```go
package config

import (
	"github.com/yuan-shuo/ysm"
)

type Config struct {
	// ...
	JwtConfig   ysm.JwtConfig
	NoJwtUrl    NoJwtUrl
	// ...
}

type NoJwtUrl struct {
	Urls []string
}
```

### yaml

配置文件格式如下

```yaml
jwtConfig:
  Secret: "<jwt_secret_key>"
  Issuer: "<service_name>"
  AccessExpire: 600 # AccessToken有效时间/s
  RefreshExpire: 6000 # RefreshToken有效时间/s
  AccessRefreshDeadLine: 300 # 每当At低于此时间, 利用Rt刷新At
  
noJwtUrl: # 无需JWT验证的url列表
  Urls:
    - "/user/login"
    - "/user/register"
    - "/test/user"
```

### 内置函数调用

示例

```go
// gozero生成双token
// 1.accessToken
accessToken, err := ysm.GenerateAccessToken(l.svcCtx.Redis, user.SnowflakeId, l.svcCtx.Config.JwtConfig)
if err != nil {
    return nil, err
}
// 2.refreshToken
var refreshToken string
if req.NeedRt {
    refreshToken, err = ysm.GenerateRefreshToken(l.svcCtx.Redis, user.SnowflakeId, l.svcCtx.Config.JwtConfig)
    if err != nil {
        return nil, err
    }
}
```