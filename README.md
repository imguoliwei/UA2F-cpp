UA2F-cpp是在[UA2F](https://github.com/Zxilly/UA2F)的基础上改写的，在此非常感谢[Zxilly](https://github.com/Zxilly/)做出的贡献。

本项目支持IPv6、多线程和清除TCP Timestamps，删除了ipset，因此使用方法可能和[UA2F](https://github.com/Zxilly/UA2F)不一样。

本人使用的x86软路由安装的是通用操作系统，而不是OpenWrt等嵌入式系统，默认的防火墙是nftables，本身就内置了set，不需要使用ipset，仅判断ct mark就足够了。

ua2f.cpp写得相对早，IPv4和IPv6的版本写在一个cpp文件，默认编译IPv4，你可以定义SELECT_IPV6，这样就会编译IPv6的版本。每个版本只能处理一种网络层协议。

ua2f-mix.cpp可以同时处理IPv4和IPv6，有最新的功能，本人现在主要运行维护ua2f-mix.cpp。

## 命令行参数

```bash
./ua2f-mix queue_start_number thread_number [--ua] [--ua-bypass] [--tcp-timestamps] [--ipid] [--disable-ct-mark]
```

| 参数               | 解释                                                         |
| ------------------ | ------------------------------------------------------------ |
| queue_start_number | 必需，指定起始 netfilter queue                               |
| thread_number      | 必需，指定工作线程数量，每个线程处理独立、递增的netfilter queue。例如，queue_start_number为10010，thread_number为4，则UA2F处理10010-10013四个netfilter queue |
| --ua               | 可选，修改netfilter queue中TCP数据包的UA                     |
| --ua-bypass        | 可选，如果某个连接被标记为不含UA (ct mark == 43)，则不检查当前数据包是否存在UA。此选项建议与 --ipid 选项搭配使用 |
| --tcp-timestamps   | 可选，清除netfilter queue中TCP SYN的Timestamps               |
| --ipid             | 可选，修改netfilter queue中IPv4数据包的ID为递增。此时应当确保WAN口的IPv4数据包都加入netfilter queue，这可能占用较多CPU资源。 |
| --disable-ct-mark  | 可选，禁止将是否存在UA的信息写入ct mark。除非UA2F与其它使用了ct mark的程序冲突，否则不建议使用此选项。 |

## 编译

### 通用操作系统用户

```bash
g++ -std=c++20 -O3 ua2f-mix.cpp -o ua2f-mix -lmnl -lnetfilter_queue -lpthread
```

请确保你的libnetfilter-queue-dev版本至少为1.0.5-2，否则编译可能出错

### OpenWrt用户参考命令

```bash
../../staging_dir/toolchain-x86_64_gcc-8.4.0_musl/bin/x86_64-openwrt-linux-g++ -std=c++17 -I ../../staging_dir/target-x86_64_musl/usr/include/ -L ../../staging_dir/target-x86_64_musl/usr/lib/ -O3 ua2f-mix.cpp -o ua2f-mix -lmnl -lnetfilter_queue -lnfnetlink -lpthread
```

OpenWrt用户运行程序前请确保你安装了以下依赖

iptables-mod-conntrack-extra iptables-mod-nfqueue libnetfilter-conntrack libnetfilter-queue libstdcpp

## nftables 配置

```bash
	chain pppoe_patch {
		type filter hook postrouting priority mangle; policy accept;
		oif "pppoe-wan" meta nfproto ipv4 counter mark set mark or 0x10 ip ttl set 64 jump ua2f
		oif "pppoe-wan" meta nfproto ipv6 counter ip6 hoplimit set 64 jump ua2f
	}

	chain ua2f {
		tcp flags syn tcp option timestamp exists counter queue num 10010-10013 fanout
		ct mark 43 counter return
		meta l4proto != tcp counter return
		tcp dport { ssh, https } counter return
		counter queue num 10010-10013 fanout
	}
```

mark set mark or 0x10 用于[rkp-ipid](https://github.com/CHN-beta/rkp-ipid)，meta mark与ct mark相互独立。

## iptables参考配置

```bash
iptables -t mangle -N ua2f
iptables -t mangle -A ua2f -m connmark --mark 43 -j RETURN
iptables -t mangle -A ua2f -p tcp -m multiport --dports 22,443 -j RETURN
iptables -t mangle -A ua2f -j NFQUEUE --queue-balance 10010:10013
iptables -t mangle -A POSTROUTING -o pppoe-wan -p tcp -j ua2f

ip6tables -t mangle -N ua2f
ip6tables -t mangle -A ua2f -m connmark --mark 43 -j RETURN
ip6tables -t mangle -A ua2f -p tcp -m multiport --dports 22,443 -j RETURN
ip6tables -t mangle -A ua2f -j NFQUEUE --queue-balance 10010:10013
ip6tables -t mangle -A POSTROUTING -o pppoe-wan -p tcp -j ua2f
```

如果UA2F发现某个连接存在UA，会将其connmark设置为44。如果你认为某个连接肯定存在UA，也可以手动将其connmark设置为44。UA2F不会将值为44的connmark设置为其他值。

如果UA2F认为某个连接不存在UA，会将其connmark设置为43。你可以直接放行connmark为43的数据包。

## Systemd配置

```ini
[Unit]
Description=UA2F for IPv4 and IPv6
After=network.target

[Service]
User=drcom
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
PrivateMounts=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectClock=true
ProtectKernelLogs=true
MemoryDenyWriteExecute=true
DynamicUser=true
RemoveIPC=true
ExecStart=/usr/bin/ua2f-mix 10010 4 --ua --tcp-timestamps

[Install]
WantedBy=multi-user.target
```

为了确保系统安全，我严格限制了程序运行时的权限。根据你的系统的实际情况，可能需要酌情修改某些选项，然后将上面的代码保存到/etc/systemd/system/ua2f.service，通过下面的命令启动UA2F

```bash
systemctl start ua2f
```



