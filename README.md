# 一个简易的HTTPS劫持程序
### 使用说明
- 系统环境：Ubuntu
- 依赖库：openssl
- 编译：执行 `make`，生成httpss可执行文件
- 运行：执行 `./https`
- 设置其他主机网关为本机IP
- 开启IP转发：`echo 1 > /proc/sys/net/ipv4/ip_forward`
- 设置端口转发：`iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 本机IP:443`
- 浏览器访问HTTPS网页，当有警告提示时，忽略警告，继续访问
### 功能说明
- 在`saveHttpsData`函数中，可以保存HTTPS解密后的明文数据
- 在`modifyHttpsData`函数中，HTTPS数据已是明文，可以篡改数据，插入JS脚本等操作