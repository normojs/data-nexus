# DATANEXUS 数据连接点

```shell
run --package pisa-proxy --bin proxy -- daemon -c examples/example-config.toml
```

```js
// 模块组成
|- root
	|- common							// 通用组件，协议解析等
	|- database
		|- sql							// https://github.dev/golang/go/tree/master/src/database/sql/sql.go
		|- mysql
		|- postgresql
	|- proxy							// 数据库代理，解析协议获取应用的数据库访问流量，并基于此实现 SQL 流量治理、访问控制、防火墙、可观测性等各种治理能力。
		|- sql							// 数据库配置拉取等：用处还不确定
  |- controller					//  Sidecar 注入、配置转换和下发等

```









![image-20240627172426409](docs/README.assets/image-20240627172426409.png)