open class MysqlPacket {
    let len: UInt8
    let id: UInt8
    public init(len: UInt8, id: UInt8){
      this.len = len
      this.id = id
    }
}
