# jwt_auth_middleware

先看at，secret校验通过+redis里有+时间还够：**过**

secret校验通过+redis里有+时间不够+有校验合格的Rt：**过**，并且增加New-Access-Token响应头通知前端更新最新的access_token（满时间，新字符串）

secret校验通过+redis里有+时间不够+没有校验合格的Rt：**过**，并且增加New-Access-Token响应头通知前端更新最新的access_token（满时间，新字符串），增加refresh_at_fail响应头通知刷新错误导致的的error

secret校验不通过/redis里没有+有校验合格的Rt：**不过**，但还是增加New-Access-Token响应头通知前端更新最新的access_token（满时间，新字符串）

校验不过+redis里没有+Rt错误：**不过**，返回http错误同时包含At和Rt的error

（RefreshToken每隔一段时间后才能刷新AccessToken，时间通过说明中的yaml配置，小于等于0则视为不考虑间隔刷新，不怕被海量新At堆满Redis可以幻想一下）

## 获取 / GET

```go
go get github.com/yuan-shuo/ysm@v1.0.0
```

## 功能函数 / Func

```go
// 1. JwtAuthMiddleware: 完整校验中间件逻辑
JwtAuthMiddleware(cfg JwtConfig, redis *redis.Redis, excludedPaths []string) rest.Middleware

// 2. GenerateAccessToken: 获取AccessToken并搭配Uid写入redis, jwtConfig包含其有效期
GenerateAccessToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error)

// 3. GenerateRefreshToken: 获取RefreshToken并搭配Uid写入redis, jwtConfig包含其有效期
GenerateRefreshToken(redis *redis.Redis, userID int64, jwtConfig JwtConfig) (string, error)
```

其中的自定义类型：

```go
type JwtConfig struct {
	AccessExpire          int    // token过期时间（秒）
	AccessTokenSecret     string // At密钥
	AccessRefreshDeadLine int    // token截止刷新时间（秒）
	RefreshExpire         int    // token刷新时间（秒）
	RefreshTimeLimit      int    // token限制刷新时间间隔（秒）
	RefreshTokenSecret    string // Rt密钥
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

    server := rest.MustNewServer(c.RestConf,
		// 设置允许跨域的域名
		rest.WithCors("http://localhost:8080"),
		rest.WithCors("http://192.168.43.49:8080/"),
		rest.WithCorsHeaders("refresh-token"),
	)
    
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
  AccessTokenSecret: "access_token_key"
  RefreshTokenSecret: "refresh_token_key"
  Issuer: "user-api"
  AccessExpire: 600 # AccessToken有效时间/s
  RefreshExpire: 6000 # RefreshToken有效时间/s
  RefreshTimeLimit: 20 # token限制刷新时间间隔/s
  AccessRefreshDeadLine: 120 # 每当At低于此时间/s, 利用Rt刷新At
  
noJwtUrl: # 无需JWT验证的url列表
  Urls:
    - "/user/login"
    - "/user/register"
    - "/test/user"
```

### 获取用户id

```go
// 获得用户uid
uid, ok := l.ctx.Value(ysm.UserIdKey{}).(int64)
if !ok {
    return nil, errors.New("user ID not found in context")
}
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