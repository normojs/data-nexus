// use mysql_parser::parser::Parser;
//
// use std::{
//     env,
//     fs::File,
//     io::{self, BufRead},
//     path::Path,
// };
//
// fn main() {
//     println!("Hello, world!");
//     let p = Parser::new();
//     let line = "SELECT * FROM user";
//     let res = p.parse(&line);
//     match res {
//         Ok(_data) => {
//             println!("ok::{:?}", _data);
//         }
//         Err(e) => {
//             println!("err::{:?}::{:?}", line, e);
//         }
//     }
// }
