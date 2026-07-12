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

use std::fs;

pub fn make_pkcs12() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let pkcs12_bytes = fs::read("./ns.panda.ltd.p12").expect("读取文件错误");
    let empty_vec: Vec<u8> = Vec::new();
    let empty_vec2: Vec<u8> = Vec::new();
    (empty_vec, empty_vec2, pkcs12_bytes)
}

// use openssl::{
//     asn1::Asn1Time,
//     hash::MessageDigest,
//     nid::Nid,
//     pkcs12::Pkcs12,
//     pkey::{PKey, Private},
//     rsa::Rsa,
//     x509::{extension::KeyUsage, X509Name, X509},
// };

// pub fn make_pkcs12() -> (Rsa<Private>, PKey<Private>, Vec<u8>) {
//     // let subject_name = "ns.pisa-proxy.io";
//     let subject_name = "ns.pandax.ltd";
//
//     let rsa_key = Rsa::generate(2048).unwrap();
//     let pub_key = PKey::from_rsa(rsa_key.clone()).unwrap();
//
//     let mut name = X509Name::builder().unwrap();
//     name.append_entry_by_nid(Nid::COMMONNAME, subject_name).unwrap();
//     let name = name.build();
//
//     let key_usage = KeyUsage::new().digital_signature().build().unwrap();
//
//     let mut builder = X509::builder().unwrap();
//     builder.set_version(2).unwrap();
//     builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
//     builder.set_not_after(&Asn1Time::days_from_now(3650).unwrap()).unwrap();
//     builder.set_subject_name(&name).unwrap();
//     builder.set_issuer_name(&name).unwrap();
//     builder.append_extension(key_usage).unwrap();
//     builder.set_pubkey(&pub_key).unwrap();
//
//     builder.sign(&pub_key, MessageDigest::sha256()).unwrap();
//     let cert = builder.build();
//
//     let pkcs12_builder = Pkcs12::builder();
//     let pkcs12 = pkcs12_builder.build("pisa-proxy", subject_name, &pub_key, &cert).unwrap();
//     let der = pkcs12.to_der().unwrap();
//
//     (rsa_key, pub_key, der)
// }

// use std::fs;
// use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};
// use rcgen::{generate_simple_self_signed, CertifiedKey};
// use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256};
// use pkcs12::Pkcs12;
use chrono::{Duration, Utc};

// pub fn make_pkcs12_v2() -> (RsaPrivateKey, Vec<u8>, Vec<u8>) {
//     let subject_name = "ns.pandax.ltd";
//
//     // 生成 2048 位 RSA 私钥
//     let mut rng = rand::thread_rng();
//     let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 密钥失败");
//     let private_key_pkcs8 = private_key.to_pkcs8_der().expect("PKCS#8 序列化失败");
//     // let private_key_der = private_key_pkcs8.as_bytes().to_vec();
//     let private_key_der = private_key_pkcs8.to_pkcs8_der().expect("PKCS#8 序列化失败");
//
//     // 将私钥导入 rcgen 的 KeyPair
//     let key_pair = KeyPair::from_der(&private_key_der).expect("创建密钥对失败");
//
//
//     // 配置证书参数
//     let mut params = CertificateParams::new(Vec::new());
//     params.alg = &PKCS_RSA_SHA256;
//     params.key_pair = Some(key_pair);
//
//     // 设置有效期
//     let now = Utc::now();
//     params.not_before = now.timestamp();
//     params.not_after = (now + Duration::days(3650)).timestamp();
//
//     // 设置主题名称
//     let mut distinguished_name = DistinguishedName::new();
//     distinguished_name.push(DnType::CommonName, subject_name);
//     params.distinguished_name = distinguished_name;
//
//     // 设置密钥用途扩展
//     params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
//
//     // 生成自签名证书
//     let cert = params.self_signed().expect("证书生成失败");
//     let cert_der = cert.serialize_der().expect("证书 DER 序列化失败");
//
//     // 构建 PKCS#12 结构
//     let pkcs12 = Pkcs12::builder()
//         .password("pisa-proxy")
//         .friendly_name(subject_name)
//         .private_key(&private_key_der)
//         .certificate(&cert_der, subject_name)
//         .build()
//         .expect("PKCS#12 构建失败");
//     let der = pkcs12.to_der().expect("PKCS#12 DER 序列化失败");
//
//     (private_key, cert_der, der)
// }
