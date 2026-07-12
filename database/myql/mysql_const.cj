// （内部线程状态)
const COM_SLEEP: UInt8 = 0x00;
// 关闭连接
const COM_QUIT: UInt8 = 0x01;
// 切换数据库
const COM_INIT_DB: UInt8 = 0x02;
// SQL查询请求
const COM_QUERY: UInt8 = 0x03;
// 获取数据表字段信息
const COM_FIELD_LIST: UInt8 = 0x04;
// 创建数据库
const COM_CREATE_DB: UInt8 = 0x05;
// 删除数据库
const COM_DROP_DB: UInt8 = 0x06;
// 清除缓存
const COM_REFRESH: UInt8 = 0x07;
// 停止服务器
const COM_SHUTDOWN: UInt8 = 0x08;
// 获取服务器统计信息
const COM_STATISTICS: UInt8 = 0x09;
// 获取当前连接的列表
const COM_PROCESS_INFO: UInt8 = 0x0A;
// （内部线程状态)
const COM_CONNECT: UInt8 = 0x0B;
// 中断某个连接
const COM_PROCESS_KILL: UInt8 = 0x0C;
// 保存服务器调试信息
const COM_DEBUG: UInt8 = 0x0D;
// 测试连通性
const COM_PING: UInt8 = 0x0E;
// （内部线程状态）
const COM_TIME: UInt8 = 0x0F;
// （内部线程状态）
const COM_DELAYED_INSERT: UInt8 = 0x10;
// 重新登陆（不断连接）
const COM_CHANGE_USER: UInt8 = 0x11;
// 获取二进制日志信息
const COM_BINLOG_DUMP: UInt8 = 0x12;
// 获取数据表结构信息
const COM_TABLE_DUMP: UInt8 = 0x13;
// （内部线程状态)
const COM_CONNECT_OUT: UInt8 = 0x14;
// 从服务器向主服务器进行注册
const COM_REGISTER_SLAVE: UInt8 = 0x15;
// 预处理SQL语句
const COM_STMT_PREPARE: UInt8 = 0x16;
// 	执行预处理语句
const COM_STMT_EXECUTE: UInt8 = 0x17;
// 发送BLOB类型的数据
const COM_STMT_SEND_LONG_DATA: UInt8 = 0x18;
// 销毁预处理语句
const COM_STMT_CLOSE: UInt8 = 0x19;
// 清除预处理语句参数缓存
const COM_STMT_RESET: UInt8 = 0x1A;
// 设置语句选项
const COM_SET_OPTION: UInt8 = 0x1B;
// 获取预处理语句的执行结果
const COM_STMT_FETCH: UInt8 = 0x1C;
// 
const COM_DAEMON: UInt8 = 0x1D;
// 
const COM_BINLOG_DUMP_GTID: UInt8 = 0x1E;
// 
const COM_RESET_CONNECTION: UInt8 = 0x1F;
