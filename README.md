UA2F-cpp是在[UA2F](https://github.com/Zxilly/UA2F)的基础上改写的，在此非常感谢[Zxilly](https://github.com/Zxilly/)做出的贡献。

本项目添加了IPv6和多进程支持，删除了ipset，因此使用方法可能和[UA2F](https://github.com/Zxilly/UA2F)不一样。

本人使用的x86软路由安装的是通用操作系统，而不是OpenWrt等嵌入式系统，默认的防火墙是nftables，本身就内置了set，不需要使用ipset，仅判断ct mark就足够了。

ua2f.cpp写得相对早，IPv4和IPv6的版本写在一个cpp文件，默认编译IPv4，你可以定义SELECT_IPV6，这样就会编译IPv6的版本。每个版本只能处理一种网络层协议。

ua2f-mix.cpp可以同时处理IPv4和IPv6，本人现在主要运行维护ua2f-mix.cpp。

你需要在运行程序时在第1个参数指定需要处理的queue_number，因此你可以同时运行多个实例，在路由器配置足够高的情况下加快处理速度。

## 编译

```bash
g++ -O3 ua2f-mix.cpp -o ua2f-mix -lmnl -lnetfilter_queue
```

## nftables 配置

```bash
	chain pppoe_patch {
		type filter hook postrouting priority mangle; policy accept;
		oif "pppoe-wan" meta nfproto ipv4 counter mark set mark or 0x10 ip ttl set 64 jump ua2f
		oif "pppoe-wan" meta nfproto ipv6 counter ip6 hoplimit set 64 jump ua2f
	}

	chain ua2f {
		ct mark 43 counter return
		meta l4proto != tcp counter return
		tcp dport { ssh, https } counter return
		counter queue num 10010-10013 fanout
	}
```

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
ExecStart=/usr/bin/ua2f-mix %i

[Install]
WantedBy=multi-user.target
```

为了确保系统安全，我严格限制了程序运行时的权限。根据你的系统的实际情况，可能需要酌情修改某些选项，然后将上面的代码保存到/etc/systemd/system/ua2f@.service，通过下面的命令启动多个UA2F实例

```bash
systemctl start ua2f@10010
systemctl start ua2f@10011
systemctl start ua2f@10012
systemctl start ua2f@10013
```



