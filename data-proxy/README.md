# Introduction

## Data-Proxy
A high performance Rust data plane used as SQL traffic proxy, support various of traffic governance capabilities.
## Feature
- [ ] mysql8使用`mysql_native_password`插件连接错误
  - [ ] https://github.com/database-mesh/pisanix/pull/170/commits/1141d1a19072ea831cd4167f5d14c39735e08396
  - [ ] https://github.com/database-mesh/pisanix/pull/172/files/915e1f0edd5f4fe66425b2eaac121e7d41f1cef2

- [ ] 支持postgresql



### Database traffic governance

Applications access databases with SQL, so Pisanix will hijack all SQL traffic. This is a great opportunity to do a lot of things around traffic, like loadbalancing and SQL firewall.

### Observability

In the past, metrics could be retrieved from database instances and display in kinds of charts. Now with Pisanix, DBAs could have more chances to achieve better observability.

### Programmable

For DBAs who could and would like to solve problems with programming. Pisanix supports many kinds of plugin mechanism, like Lua and Wasm. People will have the chance to 'reshape' the expected behavior of databases.
