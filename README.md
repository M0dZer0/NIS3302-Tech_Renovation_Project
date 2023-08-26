<p align="center">
    <h1 align="center">NIS3302-Tech_Renovation_Project</h1>
</p>
  <p align="center">
      
## Introduction
In conventional TCP/UDP communication, IP datagrams are transmitted in plaintext over the network, which poses significant security risks. Attackers can easily intercept the transmitted content using tools like Wireshark. To address this issue, our team has designed a network packet encryption and transmission system that runs in the Linux kernel space. It encrypts the data using a hook function registered on the netfilter framework's hook point and delivers the ciphertext to the recipient. We employ asymmetric RSA encryption method and exchange public keys during the communication establishment to ensure the security of the key and prevent attackers from decrypting the ciphertext.
## Preview
### Operating Environment
The required operating environment for this system is as follows:
+ Operating System: Linux distribution such as Ubuntu, Debian, CentOS, etc.
+ Kernel Version: Linux kernel version 2.6.14 or above.
+ Software Dependencies: The system requires the installation of libpcap and libnetfilter_queue.
+ Hardware Requirements: At least one network interface card (NIC) is needed.
+ System Privileges: The system should be run with root user privileges.
### Overall Design
![overall design](https://github.com/SJTUzeroking/NIS3302-Tech_Renovation_Project/blob/main/png/1.png)

![crypto module](https://github.com/SJTUzeroking/NIS3302-Tech_Renovation_Project/blob/main/png/2.png)

### How to use
To run our system, you may need to execute the shell communication script we have written for key distribution. The command to run is as follows:

```shell
sh ./socket.sh <server/client> <TCP/UDP> <目标IP> <端口号 >
```

Please make sure you have the necessary permissions and dependencies in place before running the script.
Afterward, you need to insert the compiled encryption and decryption module into the system kernel and provide the required configuration rules. Here are the steps to follow:

1. Insert the module into the kernel:

```shell
insmod encryption_module.ko
```

Replace `encryption_module.ko` with the actual name of your compiled module.

2. Configure the necessary rules:

```shell
./configure -p tcp/udp -x src_addr -y des_addr/-m srcport -n desport
```

Please note that inserting a module into the kernel and configuring system rules require root privileges. Make sure you have the necessary permissions before executing these commands.

Please ensure that the parameters entered are correct, and then you can communicate to test the encryption effect.
For more details,you can refer to the source code or our **system test** folder introduced in Chinese.



**Our Team**
<br/>[@ChubbyChenJK](https://github.com/ChubbyChenJK)
<br/>[@cyChen2003](https://github.com/cyChen2003)
<br/>[@Zichuan-c](https://github.com/Zichuan-c)
<br/>[@vagueeee](https://github.com/vagueeee)
<br/>[@SJTUzeroking](https://github.com/SJTUzeroking)
## Special Thanks
[lk_crypto_test](https://github.com/alekseymmm/lk_crypto_test)&emsp;From alekseymmm's repository on GitHub

[Linux的SOCKET编程详解](https://blog.csdn.net/hguisu/article/details/7445768/)&emsp;From hguisu's blog on CSDN

[信息安全课程9：raw socket编程](https://zhuanlan.zhihu.com/p/59327439)&emsp;From ustcsse308 on Zhihu

[Linux 网络层收发包流程及 Netfilter 框架浅析](https://zhuanlan.zhihu.com/p/93630586)&emsp;From Tencent-tech on Zhihu

## References
[信息安全技术解析与开发实践](https://baike.baidu.com/item/信息安全技术解析与开发实践/5613826?fr=aladdin)
<br/>訾小超 薛质 姚立红 蒋兴浩 潘理编著&emsp;李建华主审&emsp;清华大学出版社.2011

[深入理解计算机系统](https://baike.baidu.com/item/深入理解计算机系统/4542223?fr=aladdin)
<br/>Bryant,R.E.等编著&emsp;龚奕利 贺莲译&emsp;机械工业出版社.2016

[计算机网络：自顶向下方法](https://baike.baidu.com/item/计算机网络：自顶向下方法（原书第7版）/52701817?fromModule=search-result_lemma)
<br/>James，F.Kurose，Keith，W.Ross编著&emsp;陈鸣译&emsp;机械工业出版社.2018
