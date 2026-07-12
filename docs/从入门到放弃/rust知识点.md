# Arc

线程安全的引用计数指针。 “Arc”代表“原子引用计数 Atomically Reference Counted”

Arc 类型提供在堆中分配的 T 类型值的共享所有权（shared ownership）。*** 在 Arc 上调用克隆会生成一个新的 Arc 实例，该实例指向堆上与源 Arc 相同的分配，同时增加引用计数。**当指向给定分配的最后一个 Arc 指针被销毁时，存储在该分配中的值（通常称为“内部值”）也会被删除。

