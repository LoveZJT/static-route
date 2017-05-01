# static-route
静态路由编程实现
>* 按照上图的网络拓扑，搭建网络，注意，所有 PC 和路由器不要设置 IP 地址。
>* 在 PC1 和 PC2 上建立自己的 ARP 表和 IP 表，用 Raw Socket 实现收发 ICMP 包的程序。
>* 在 Router1 和 Router2 上建立自己的 ARP 表、IP 表和路由表，用 Raw Socket 实现 IP 包
的静态路由转发程序。
>* 在每个 PC 和 router 上运行 ifconfig，确保 IP 地址为空，截屏。
>* 用第 2 步的收发包程序，从 PC1 ping PC2，把运行结果以及 Wireshark 的抓包结果进行
截屏和分析。
