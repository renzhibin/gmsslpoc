#0 版本
gmssl version
#1 生成CA证书
#1.1 生成根证书
# 生成根证书私钥->生成根证书->查看根证书
gmssl sm2keygen -pass 1234 -out ca/rootcakey.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O CSITS -OU CS -CN ROOTCA -days 3650 -key ca/rootcakey.pem -pass 1234 -out ca/rootcacert.pem -key_usage keyCertSign -key_usage cRLSign
gmssl certparse -in ca/rootcacert.pem

#1.2 生成子证书
# 生成子证书私钥->生成req->生成子证书
gmssl sm2keygen -pass 1234 -out ca/subcakey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O CSITS -OU CS -CN "Sub CA" -key ca/subcakey.pem -pass 1234 -out ca/subcareq.pem
gmssl reqsign -in ca/subcareq.pem -days 365 -key_usage keyCertSign -path_len_constraint 0 -cacert ca/rootcacert.pem -key ca/rootcakey.pem -pass 1234 -out ca/subcacert.pem

#2 生成dtms端证书
gmssl sm2keygen -pass 1234 -out dtmskey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O CSITS -OU CS -CN localhost -key dtmskey.pem -pass 1234 -out dtmsreq.pem
gmssl reqsign -in dtmsreq.pem -days 365 -key_usage digitalSignature  -key_usage keyEncipherment -cacert ca/subcacert.pem -key ca/subcakey.pem -pass 1234 -out dtmscert.pem

gmssl certparse -in dtmscert.pem
gmssl certverify -in dtmscert.pem -cacert ca/rootcacert.pem

#3 生成datasend端证书
gmssl sm2keygen -pass 1234 -out datasendkey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O CSITS -OU CS -CN localhost -key datasendkey.pem -pass 1234 -out datasendreq.pem
gmssl reqsign -in datasendreq.pem -days 365 -key_usage digitalSignature  -key_usage keyEncipherment -cacert ca/subcacert.pem -key ca/subcakey.pem -pass 1234 -out datasendcert.pem
#4 生成datareceive端证书
gmssl sm2keygen -pass 1234 -out datareceivekey.pem
gmssl reqgen -C CN -ST Beijing -L Haidian -O CSITS -OU CS -CN localhost -key datareceivekey.pem -pass 1234 -out datareceivereq.pem
gmssl reqsign -in datareceivereq.pem -days 365 -key_usage digitalSignature  -key_usage keyEncipherment -cacert ca/subcacert.pem -key ca/subcakey.pem -pass 1234 -out datareceivecert.pem
