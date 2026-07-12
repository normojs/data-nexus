// Copyright 2022 SphereEx Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use iota::iota;

pub const MIN_PROTOCOL_VERSION: u8 = 10;
pub const MAX_PAYLOAD_LEN: usize = (1 << 24) - 1;

pub const OK_HEADER: u8 = 0x00;
pub const ERR_HEADER: u8 = 0xff;
pub const EOF_HEADER: u8 = 0xfe;
pub const MORE_DATA_HEADER: u8 = 0x01;
pub const LOCAL_IN_FILE_HEADER: u8 = 0xfb;
pub const CACHE_SHA2_FAST_AUTH: u8 = 0x03;
pub const CACHE_SHA2_FULL_AUTH: u8 = 0x04;

pub const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
pub const SERVER_STATUS_NO_GOOD_INDEX_USED: u16 = 0x0010;
pub const SERVER_STATUS_NO_INDEX_USED: u16 = 0x0020;
pub const SERVER_STATUS_CURSOR_EXISTS: u16 = 0x0040;
pub const SERVER_STATUS_LAST_ROW_SEND: u16 = 0x0080;
pub const SERVER_STATUS_DB_DROPPED: u16 = 0x0100;
pub const SERVER_STATUS_NO_BACKSLASH_ESCAPED: u16 = 0x0200;
pub const SERVER_STATUS_METADATA_CHANGED: u16 = 0x0400;
pub const SERVER_QUERY_WAS_SLOW: u16 = 0x0800;
pub const SERVER_PS_OUT_PARAMS: u16 = 0x1000;
pub const SERVER_SESSION_STATE_CHANGED: u16 = 0x4000;

//TODO: change to enum
pub const AUTH_MYSQL_OLD_PASSWORD: &str = "mysql_old_password";
pub const AUTH_CACHING_SHA2_PASSWORD: &str = "caching_sha2_password";
pub const AUTH_SHA256_PASSWORD: &str = "sha256_password";
pub const AUTH_NATIVE_PASSWORD: &str = "mysql_native_password";

iota! {
    pub const COM_SLEEP :u8 = iota;
         ,COM_QUIT
         ,COM_INIT_DB
         ,COM_QUERY
         ,COM_FIELD_LIST
         ,COM_CREATE_DB
         ,COM_DROP_DB
         ,COM_REFRESH
         ,COM_SHUTDOWN
         ,COM_STATISTICS
         ,COM_PROCESS_INFO
         ,COM_CONNECT
         ,COM_PROCESS_KILL
         ,COM_DEBUG
         ,COM_PING
         ,COM_TIME
         ,COM_DELAYED_INSERT
         ,COM_CHANGE_USER
         ,COM_BINLOG_DUMP
         ,COM_TABLE_DUMP
         ,COM_CONNECT_OUT
         ,COM_REGISTER_SLAVE
         ,COM_STMT_PREPARE
         ,COM_STMT_EXECUTE
         ,COM_STMT_SEND_LONG_DATA
         ,COM_STMT_CLOSE
         ,COM_STMT_RESET
         ,COM_SET_OPTION
         ,COM_STMT_FETCH
         ,COM_DAEMON
         ,COM_BINLOG_DUMP_GTID
         ,COM_RESET_CONNECTION
}

/// 定义通信类型枚举
#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u8)]
pub enum ComType {
    /// 睡眠命令
    SLEEP,
    /// 退出命令
    QUIT,
    /// 初始化数据库命令
    INIT_DB,
    /// 查询命令
    QUERY,
    /// 获取字段列表命令
    FIELD_LIST,
    /// 创建数据库命令
    CREATE_DB,
    /// 删除数据库命令
    DROP_DB,
    /// 刷新命令，如刷新表、日志等
    REFRESH,
    /// 关闭服务器命令
    SHUTDOWN,
    /// 统计信息命令
    STATISTICS,
    /// 进程信息命令
    PROCESS_INFO,
    /// 连接命令
    CONNECT,
    /// 进程终止命令
    PROCESS_KILL,
    /// 调试命令
    DEBUG,
    /// 心跳命令
    PING,
    /// 时间命令，返回服务器时间
    TIME,
    /// 延迟插入命令
    DELAYED_INSERT,
    /// 更改用户命令
    CHANGE_USER,
    /// 二进制日志dump命令
    BINLOG_DUMP,
    /// 表转储命令
    TABLE_DUMP,
    /// 连接外出命令
    CONNECT_OUT,
    /// 注册从服务器命令
    REGISTER_SLAVE,
    /// 准备语句命令
    STMT_PREPARE,
    /// 执行准备语句命令
    STMT_EXECUTE,
    /// 发送长数据命令
    STMT_SEND_LONG_DATA,
    /// 关闭准备语句命令
    STMT_CLOSE,
    /// 重置准备语句命令
    STMT_RESET,
    /// 设置选项命令
    SET_OPTION,
    /// 获取准备语句结果命令
    STMT_FETCH,
    /// 守护进程命令
    DAEMON,
    /// 基于GTID的二进制日志dump命令
    BINLOG_DUMP_GTID,
    /// 重置连接命令，用于重用连接而不必重新建立
    RESET_CONNECTION,
}

impl From<u8> for ComType {
    #[inline]
    fn from(t: u8) -> ComType {
        unsafe { std::mem::transmute::<u8, ComType>(t) }
    }
}

impl AsRef<str> for ComType {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            Self::SLEEP => "sleep",
            Self::QUIT => "quit",
            Self::INIT_DB => "init_db",
            Self::QUERY => "query",
            Self::FIELD_LIST => "field_list",
            Self::CREATE_DB => "create_db",
            Self::DROP_DB => "drop_db",
            Self::REFRESH => "refresh",
            Self::SHUTDOWN => "shutdown",
            Self::STATISTICS => "statistics",
            Self::PROCESS_INFO => "process_info",
            Self::CONNECT => "connect",
            Self::PROCESS_KILL => "process_kill",
            Self::DEBUG => "debug",
            Self::PING => "ping",
            Self::TIME => "time",
            Self::DELAYED_INSERT => "delayed_insert",
            Self::CHANGE_USER => "change_user",
            Self::BINLOG_DUMP => "binlog_dump",
            Self::TABLE_DUMP => "table_dump",
            Self::CONNECT_OUT => "connect_out",
            Self::REGISTER_SLAVE => "register_slave",
            Self::STMT_PREPARE => "stmt_prepare",
            Self::STMT_EXECUTE => "stmt_execute",
            Self::STMT_SEND_LONG_DATA => "stmt_send_long_data",
            Self::STMT_CLOSE => "stmt_close",
            Self::STMT_RESET => "stmt_reset",
            Self::SET_OPTION => "set_option",
            Self::STMT_FETCH => "stmt_fetch",
            Self::DAEMON => "daemon",
            Self::BINLOG_DUMP_GTID => "binlog_dump_gtid",
            Self::RESET_CONNECTION => "reset_connection",
        }
    }
}

iota! {
    pub const CLIENT_LONG_PASSWORD: u32 = 1 << iota; // 表示客户端支持长密码认证。
         ,CLIENT_FOUND_ROWS // 表示客户端只关心查询结果的行数，而不关心列名。
         ,CLIENT_LONG_FLAG // 表示客户端支持长查询字符串
         ,CLIENT_CONNECT_WITH_DB // 表示客户端连接时需要指定数据库名称。
         ,CLIENT_NO_SCHEMA // 表示客户端连接时不需要指定数据库模式
         ,CLIENT_COMPRESS // 表示客户端支持压缩传输。
         ,CLIENT_ODBC // 表示客户端支持ODBC协议。
         ,CLIENT_LOCAL_FILES // 表示客户端支持本地文件访问。
         ,CLIENT_IGNORE_SPACE // 表示客户端忽略空格。
         ,CLIENT_PROTOCOL_41 // 表示客户端支持MySQL协议4.1。
         ,CLIENT_INTERACTIVE // 表示客户端是交互式客户端。
         ,CLIENT_SSL // 表示客户端支持SSL加密。
         ,CLIENT_IGNORE_SIGPIPE // 表示客户端忽略SIGPIPE信号。
         ,CLIENT_TRANSACTIONS // 表示客户端支持事务。
         ,CLIENT_RESERVED // 表示客户端支持保留字。
         ,CLIENT_SECURE_CONNECTION // 表示客户端支持安全连接。
         ,CLIENT_MULTI_STATEMENTS // 表示客户端支持多语句。
         ,CLIENT_MULTI_RESULTS // 表示客户端支持多结果集。
         ,CLIENT_PS_MULTI_RESULTS // 表示客户端支持存储过程的多结果集。
         ,CLIENT_PLUGIN_AUTH // 表示客户端支持插件认证。
            /*
            CLIENT_CONNECT_ATTRS 是 MySQL 8.0 引入的一个客户端标志位，它属于 CLIENT_FLAGS 集合中的一部分。
            这个标志位允许客户端在连接时向服务器传递一组属性，这些属性可以是任何键值对，用于提供有关客户端或连接本身的额外信息。
            当客户端设置了这个标志位，并在连接请求中包含了 connect_attrs 字段时，服务器会接收到这些属性，并可以在后续的操作中使用它们。
            例如，这些属性可以用于身份验证插件、日志记录、审计或其他任何需要额外上下文信息的场景。
            connect_attrs 是一个 JSON 对象，其中包含了一系列的键值对。每个键值对都代表了一个属性，键是属性的名称，值是属性的值。
            */
         ,CLIENT_CONNECT_ATTRS // 表示客户端支持连接属性。
        /*
            在 MySQL 的身份验证插件机制中，某些插件可能需要传递额外的数据给服务器，这些数据可能是身份验证的一部分。
            这些数据通常是长度编码的，这意味着数据前面有一个表示数据长度的字段。
            当客户端设置了这个标志位 (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)，它告诉服务器它准备发送长度编码的插件认证数据。
            服务器会相应地处理这些数据，并使用相应的身份验证插件进行身份验证。
        */
         ,CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA // 表示客户端支持长度编码的客户端数据。
         ,CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS // 表示客户端可以处理过期密码。
         ,CLIENT_SESSION_TRACK // 表示客户端支持会话跟踪。
}

/// 定义了与MySQL数据库兼容的列类型枚举
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ColumnType {
    MYSQL_TYPE_DECIMAL,           // 定点数
    MYSQL_TYPE_TINY,              // 1字节的整数
    MYSQL_TYPE_SHORT,             // 2字节的短整数
    MYSQL_TYPE_LONG,              // 4字节的长整数
    MYSQL_TYPE_FLOAT,             // 单精度浮点数
    MYSQL_TYPE_DOUBLE,            // 双精度浮点数
    MYSQL_TYPE_NULL,              // NULL类型
    MYSQL_TYPE_TIMESTAMP,         // 时间戳
    MYSQL_TYPE_LONGLONG,          // 8字节的长整数
    MYSQL_TYPE_INT24,             // 3字节的整数
    MYSQL_TYPE_DATE,              // 日期
    MYSQL_TYPE_TIME,              // 时间
    MYSQL_TYPE_DATETIME,          // 日期和时间
    MYSQL_TYPE_YEAR,              // 年份
    MYSQL_TYPE_NEWDATE,           // 新日期类型
    MYSQL_TYPE_VARCHAR,           // 可变长度字符串
    MYSQL_TYPE_BIT,               // 位数据
    MYSQL_TYPE_NEWDECIMAL = 0xf6, // 新的十进制类型，提供了更高的精度
    MYSQL_TYPE_ENUM,              // 枚举类型，允许在一个字段中存储一个预定义集合中的值
    MYSQL_TYPE_SET,               // 集合类型，用于存储多个值在一个字段中
    MYSQL_TYPE_TINY_BLOB,         // 小型可变长度二进制字符串
    MYSQL_TYPE_MEDIUM_BLOB,       // 中型可变长度二进制字符串
    MYSQL_TYPE_LONG_BLOB,         // 大型可变长度二进制字符串
    MYSQL_TYPE_BLOB,              // 可变长度二进制字符串的通用类型
    MYSQL_TYPE_VAR_STRING,        // 可变长度字符串
    MYSQL_TYPE_STRING,            // 字符串
    MYSQL_TYPE_GEOMETRY,          // 几何数据类型
}

impl From<u8> for ColumnType {
    #[inline]
    fn from(t: u8) -> ColumnType {
        unsafe { std::mem::transmute::<u8, ColumnType>(t) }
    }
}

impl AsRef<str> for ColumnType {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            ColumnType::MYSQL_TYPE_DECIMAL => "decimal",
            ColumnType::MYSQL_TYPE_TINY => "tiny",
            ColumnType::MYSQL_TYPE_SHORT => "short",
            ColumnType::MYSQL_TYPE_LONG => "long",
            ColumnType::MYSQL_TYPE_FLOAT => "float",
            ColumnType::MYSQL_TYPE_DOUBLE => "double",
            ColumnType::MYSQL_TYPE_NULL => "null",
            ColumnType::MYSQL_TYPE_TIMESTAMP => "timestamp",
            ColumnType::MYSQL_TYPE_LONGLONG => "longlong",
            ColumnType::MYSQL_TYPE_INT24 => "int24",
            ColumnType::MYSQL_TYPE_DATE => "date",
            ColumnType::MYSQL_TYPE_TIME => "time",
            ColumnType::MYSQL_TYPE_DATETIME => "datetime",
            ColumnType::MYSQL_TYPE_YEAR => "year",
            ColumnType::MYSQL_TYPE_NEWDATE => "newdate",
            ColumnType::MYSQL_TYPE_VARCHAR => "varchar",
            ColumnType::MYSQL_TYPE_BIT => "bit",
            ColumnType::MYSQL_TYPE_NEWDECIMAL => "new_decimal",
            ColumnType::MYSQL_TYPE_ENUM => "enum",
            ColumnType::MYSQL_TYPE_SET => "set",
            ColumnType::MYSQL_TYPE_TINY_BLOB => "tiny_blob",
            ColumnType::MYSQL_TYPE_MEDIUM_BLOB => "medium_blob",
            ColumnType::MYSQL_TYPE_LONG_BLOB => "long_blob",
            ColumnType::MYSQL_TYPE_BLOB => "tiny_blob",
            ColumnType::MYSQL_TYPE_VAR_STRING => "var",
            ColumnType::MYSQL_TYPE_STRING => "string",
            ColumnType::MYSQL_TYPE_GEOMETRY => "geometry",
        }
    }
}

// Column flag, see https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__column__definition__flags.html
// Column flag is 2 bytes
/// 定义了与数据库列属性相关的枚举。
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
#[repr(u16)]
pub enum ColumnFlag {
    /// 列不接受空值。
    NOT_NULL_FLAG = 1,
    /// 列是主键。
    PRI_KEY_FLAG = 2,
    /// 列是唯一键。
    UNIQUE_KEY_FLAG = 4,
    /// 列包含多个键。
    MULTIPLE_KEY_FLAG = 8,
    /// 列类型为BLOB（二进制大对象）。
    BLOB_FLAG = 16,
    /// 列值为无符号数。
    UNSIGNED_FLAG = 32,
    /// 列值填充为零。
    ZEROFILL_FLAG = 64,
    /// 列值以二进制方式存储。
    BINARY_FLAG = 128,
    /// 列类型为ENUM。
    ENUM_FLAG = 256,
    /// 列值自动递增。
    AUTO_INCREMENT_FLAG = 512,
    /// 列值为时间戳。
    TIMESTAMP_FLAG = 1024,
    /// 列值在更新时设置为当前时间。
    SET_FLAG = 2048,
    /// 列没有默认值。
    NO_DEFAULT_VALUE_FLAG = 4096,
    /// 列在更新时自动设置为当前时间。
    ON_UPDATE_NOW_FLAG = 8192,
    /// 列是部分键的一部分。
    PART_KEY_FLAG = 16384,
    /// 列类型为数值。
    NUM_FLAG = 32768,
}

impl From<u16> for ColumnFlag {
    #[inline]
    fn from(t: u16) -> ColumnFlag {
        unsafe { std::mem::transmute::<u16, ColumnFlag>(t) }
    }
}

impl AsRef<str> for ColumnFlag {
    #[inline]
    fn as_ref(&self) -> &str {
        match self {
            ColumnFlag::NOT_NULL_FLAG => "not_null",
            ColumnFlag::PRI_KEY_FLAG => "pri_key",
            ColumnFlag::UNIQUE_KEY_FLAG => "unique_key",
            ColumnFlag::MULTIPLE_KEY_FLAG => "multiple_key",
            ColumnFlag::BLOB_FLAG => "blob",
            ColumnFlag::UNSIGNED_FLAG => "unsigned",
            ColumnFlag::ZEROFILL_FLAG => "zerofill",
            ColumnFlag::BINARY_FLAG => "binary",
            ColumnFlag::ENUM_FLAG => "enum",
            ColumnFlag::AUTO_INCREMENT_FLAG => "auto_increment",
            ColumnFlag::TIMESTAMP_FLAG => "timestamp",
            ColumnFlag::SET_FLAG => "set",
            ColumnFlag::NO_DEFAULT_VALUE_FLAG => "no_default",
            ColumnFlag::ON_UPDATE_NOW_FLAG => "on_update_now",
            ColumnFlag::PART_KEY_FLAG => "part_key",
            ColumnFlag::NUM_FLAG => "num",
        }
    }
}

#[allow(dead_code)]
const AUTH_NAME: &str = "mysql_native_password";

pub const CACHING_SHA2_PASSWORD_REQUEST_PUBLIC_KEY: i64 = 2;
pub const CACHING_SHA2_PASSWORD_FAST_AUTH_SUCCESS: i64 = 3;
pub const CACHING_SHA2_PASSWORD_PERFORM_FULL_AUTHENTICATION: i64 = 4;

use num_derive::FromPrimitive;

#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum Com {
    Sleep = 0,
    Quit,
    InitDb,
    Query,
    FieldList,
    CreateDb,
    DropDb,
    Refresh,
    Shutdown,
    Statistics,
    ProcessInfo,
    Connect,
    ProcessKill,
    Debug,
    Ping,
    Time,
    DelayedInsert,
    ChangeUser,
    BinlogDump,
    TableDump,
    ConnectOut,
    RegisterSlave,
    StmtPrepare,
    StmtExecute,
    StmtSendLongData,
    StmtClose,
    StmtReset,
    SetOption,
    StmtFetch,
    Daemon,
    BinlogDumpGtid,
    ResetConnection,
}

#[cfg(test)]
mod test {
    use super::{ColumnFlag, ColumnType};

    #[test]
    fn test_column_type() {
        let t = ColumnType::MYSQL_TYPE_DATE;
        assert_eq!(t as u8, 0x0a);

        let columt_type = ColumnType::from(0x0a);
        assert_eq!(columt_type, ColumnType::MYSQL_TYPE_DATE);

        assert_eq!(columt_type.as_ref(), "date")
    }

    #[test]
    fn test_column_flag() {
        let t = ColumnFlag::ENUM_FLAG;
        assert_eq!(t as u16, 0x100);

        let column_flag = ColumnFlag::from(0x100);
        assert_eq!(column_flag, ColumnFlag::ENUM_FLAG);

        assert_eq!(column_flag.as_ref(), "enum");
    }
}
