keytool -genkeypair \
  -alias datanexus \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore ns.pandax.ltd.p12 \
  -dname "CN=ns.pandax.ltd, OU=DataNexus, O=mbu, L=xuzhou, ST=jiangsu, C=cn" \
  -validity 3650 \
  -storepass "data-nexus" \
  -keypass "data-nexus"


#  生成私钥
#openssl genpkey -algorithm RSA -out private.key
