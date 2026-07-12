use std::rc::Rc;
use std::ptr;
fn main() {

    // @see https://zhuanlan.zhihu.com/p/603465225
    let s: Rc<String> = Rc::new("hello".to_string());
    let t: Rc<String> = s.clone();
    let u: Rc<String> = s.clone();
    println!("{} {} {}", s, t, u);
    // false 为什么？
    println!("{}", ptr::addr_of!(s) == ptr::addr_of!(t));

    let s1 = String::from("hello");
    let s2 = s1.clone();
    let mut s3 = s2.clone();
    println!("{} {} {}", s1, s2, s3);
    println!("{} {}", s1 == s2, s2==s3);
}
