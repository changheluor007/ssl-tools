## 💻About

- For a more secure network environment, self built Ca and self issued SSL certificate
- 为了更安全的网络环境 自建 CA 并自签发 SSL 证书
- Remember to check [Debug](#Debug)
- 记得查看 [Debug](#Debug)
- <b>推荐 [ssleye](https://www.ssleye.com/self_sign.html) [myssl](https://myssl.com/create_test_cert.html) [sslchecker](https://www.sslchecker.com/csr/self_signed) 在线生成根证书</b>
- Thanks [shaneutt](https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251)

## 👍Help

Thank you [AndroidOL](https://post.m.smzdm.com/p/715145/)  for your help !

```bash
Usage of sslt:
  -commonname string
        Specified commonName (default "GTS Root R1")
  -hostname string
        Specified domain name (default "localhost")
./sslt --hostname test.com --commonname test
```

## 🗼Debug

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/sslt_linux_amd64 sslt.go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/sslt_linux_arm64 sslt.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/sslt_mac_amd64 sslt.go
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/sslt_mac_arm64 sslt.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/sslt_windows_amd64.exe sslt.go
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o bin/sslt_windows_arm64.exe sslt.go
```
