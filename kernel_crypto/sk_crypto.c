#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <net/sock.h>
#define MAX_BUFFER_SIZE 1024            // 密钥读取时的函数参数
#define MATCH	1           // IP地址和端口匹配函数的返回值
#define NMATCH	0           

// 与控制规则有关的全局变量
unsigned int controlled_protocol = 0;   // 协议类型
unsigned short controlled_srcport = 0;  // 源端口
unsigned short controlled_dstport = 0;  // 目标端口
unsigned int controlled_saddr = 0;      // 源地址
unsigned int controlled_daddr = 0;      // 目标地址
// 匹配控制规则时，对控制信息不区分源/目标，统一视为控制的通信两方
int enable_flag = 0;                    //启用控制规则标志位，启用则置为 1
// 保存报文信息的全局变量
struct sk_buff *tmpskb;         // 指向本次处理报文的指针
struct iphdr *piphdr;           // 指向本次处理报文的ip头部的指针
// 用于挂载钩子函数的全局变量
struct nf_hook_ops nfho_in;             // 在输入端解密的钩子函数
struct nf_hook_ops nfho_out;            // 在输出端加密的钩子函数

// 存储加密操作结果的结构体
struct tcrypt_result        
{
    struct completion completion;
    int err;
};
// 存储密钥内容和长度
struct my_key {
    unsigned char *data;
    int length;
};

// 与加解密操作有关的全局变量
struct my_key priv_key;         // 私钥
struct my_key pub_key;          // 公钥
unsigned int out_len_max = 0;   // RSA 加解密的最大输出长度

// 重新计算TCP校验和
void recalculate_tcp_checksum(struct sk_buff *skb) 
{
    struct tcphdr *tcph;
    struct iphdr *iph;

    // 获取 TCP 头部和 IP 头部指针
    tcph = tcp_hdr(skb);
    iph = ip_hdr(skb);

    // 重新计算 TCP 校验和
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4),
                IPPROTO_TCP,csum_partial(tcph, (ntohs(iph ->tot_len)-iph->ihl*4), 0));

}

// 重新计算UDP校验和
void recalculate_udp_checksum(struct sk_buff *skb)
{
    struct udphdr *udph;
    struct iphdr *iph;

    // 获取 UDP 头部和 IP 头部指针
    udph = udp_hdr(skb);
    iph = ip_hdr(skb);

    // 重新计算 UDP 校验和
    iph->check=0;
    iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4), 
                IPPROTO_UDP,csum_partial(udph, (ntohs(iph ->tot_len)-iph->ihl*4), 0));
   
}

/**
 * @brief 读取密钥
 * 从存储有公私钥的文件中读取密钥到缓冲区
 * 
 * @param filename 文件名
 * @param flag 公钥 flag == 0, 私钥 flag == 1
 * @return 读取的密钥长度
 */
static int read_file(const char *filename, int flag)
{
    struct file *file;
    mm_segment_t oldfs;
    int bytes_read = 0;
    
    // 打开文件
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ALERT "Failed to open file\n");
        return -1;
    }
    // 切换到内核空间的地址空间
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    if (flag == 0)
    {
        // 公钥
        bytes_read = vfs_read(file, pub_key.data, MAX_BUFFER_SIZE, &file->f_pos); // vfs_read函数的四个参数分别是文件指针，缓冲区指针，缓冲区大小，文件指针的偏移量
        pub_key.length = bytes_read;
    }
    else
    {
        // 私钥
        bytes_read = vfs_read(file, priv_key.data, MAX_BUFFER_SIZE, &file->f_pos); // vfs_read函数的四个参数分别是文件指针，缓冲区指针，缓冲区大小，文件指针的偏移量
        priv_key.length = bytes_read;
    }
    // 恢复地址空间
    set_fs(oldfs);
    // 关闭文件
    filp_close(file, NULL);

    return bytes_read;
}

// 输出加解密后的内容
static inline void hexdump(unsigned char *buf, unsigned int len)
{
    while (len--)
        printk("%02x", *buf++);
    printk("\n");
}

// 检查字符串长度，去除空格和空字符
static void check_length(unsigned char *buf, unsigned int *len)
{
    int i = 0;
    while (buf[i] == '\0') {
        i++;
        (*len)--;
    }
    memmove(buf, buf + i, *len);    // 移动字符串，将字符串前面的空格去掉，防止内存泄漏
    buf[*len] = '\0';   // 添加字符串结束符
}

// 异步操作回调函数
static void tcrypt_complete(struct crypto_async_request *req, int err)
{
    struct tcrypt_result *res = req->data;
    if (err == -EINPROGRESS)
        return;
    res->err = err;
    complete(&res->completion);
}

// 等待异步操作完成
static int wait_async_op(struct tcrypt_result *tr, int ret)
{
    //检查返回值查看异步操作是否进行中
    if (ret == -EINPROGRESS || ret == -EBUSY)
    {
        wait_for_completion(&tr->completion);
        reinit_completion(&tr->completion);
        ret = tr->err;
    }
    return ret;
}

/**
 * @brief 加密函数
 * 调用linux内核中的加解密模块对指定报文数据进行RSA加密,并同步更新sk_buff数据空间，修改其中的长度字段。
 * 
 * @param skb: 指向待加密报文的指针；
 * @param protocol 通信协议类型 (protocol == 6: TCP,  protcol == 17: UDP)；
 * @return int err：指示加密操作是否成功。正常返回err=1，如果发生错误返回，err=0；
 */
static int encrypt_data(struct sk_buff *skb, unsigned int protocol)
{
    printk("encrypt starting...");
    
    struct scatterlist src, dst;        //两个散列表，分别存储输入和输出数据
    struct akcipher_request *req;
    struct crypto_akcipher *tfm;
    struct tcrypt_result result;
    struct tcphdr *tcphdr;              //指向tcp报文头部的指针
    struct udphdr *udphdr;              //指向udp报文头部的指针
    unsigned char *payload = NULL;      // 指向有效载荷数据的起始位置
    unsigned int payload_len = 0;       // 记录有效载荷数据的长度

    int err = -ENOMEM;                  // 错误码，用于错误检测和函数返回
    unsigned char *str = (unsigned char *)"exit";           // tcp通信的退出信息，用于跳过对报文流中的tcp退出信息加密
    
    // 获取指向有效荷载数据的指针，以及有效荷载数据的长度
    // 
    // 指针payload：数据区域指针 +  ip 头长度 + tcp / udp 头长度
    // 长度payload_len：总长度 - ip 头长度 - tcp / udp 报文头长度
    // 
    // 注：
    // 对tcp报文，跳过对 exit 信息 和 接收方回复的 ACK 包加解密

    switch(protocol) {
        case 17: //UDP
            payload = ((unsigned char *)tmpskb->data + (piphdr->ihl * 4) + sizeof(struct udphdr));
            payload_len = skb->len - skb_transport_offset(skb) - sizeof(struct udphdr);
            break;
        case 6: //TCP  
            tcphdr = tcp_hdr(skb);
            unsigned int tcphdr_len = tcphdr->doff * 4;
            payload = (unsigned char *)tcphdr + tcphdr_len;
            payload_len = skb->len - skb_transport_offset(skb) - tcphdr_len;
            // printk("tcphdr->doff: %d\n", tcphdr->doff);
            // printk("tcphdr->psh: %d\n", tcphdr->psh);
            // 对tcp的 'exit' 退出信息不加密
            if(!strncmp(str, payload, payload_len))       
            {
                printk("This is a exit message");
                err = 1;
                return err;
            }
            // 对接收方回复的 ACK 确认包不进行加密
            else if(payload_len == 0 && tcphdr->ack)                   
            {
                printk("This is a ACK message");
                err = 1;
                return err; 
            }
            break;
        default:
            return err;
    }
    // 创建缓冲区，存储输入和输出数据
    void *inbuf = NULL;
    inbuf = kzalloc(payload_len, GFP_KERNEL);
    memcpy(inbuf, payload, payload_len);
    hexdump(inbuf, payload_len);
    kfree(inbuf);
    
    // 创建临时缓冲区，存储加解密操作的输入和输出数据
    void *xbuf = NULL;
    void *outbuf = NULL;
    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);                                  
    if (!xbuf)
        return err;
    
    // 创建密钥句柄
    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);             
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate key handle\n");
        goto out_free_xbuf;
    }

    // 分配请求对象
    req = akcipher_request_alloc(tfm, GFP_KERNEL);                       
    if (!req) {
        printk(KERN_ERR "Failed to allocate request object\n");
        goto out_free_tfm;
    }
   // 设置RSA公钥
    err = crypto_akcipher_set_pub_key(tfm, pub_key.data, pub_key.length);
    if (err) {
        printk(KERN_ERR "Failed to set RSA public key\n");
        goto out_free_req;
    }

    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);                             // 全局变量，赋值为rsa加密可输出的最大长度
    
    // 关于加解密数据长度：
    // 
    // RSA加解密算法的明文必须小于密钥长度
    // 加密时得到的密文等于密钥长度，长度不够会自动进行补零操作
    // 解密时对和公钥长度相等的密文进行解密

    // 对短报文直接进行加解密处理
    if(payload_len < out_len_max)      
    {         
        outbuf = kzalloc(out_len_max, GFP_KERNEL);                              
        if (!outbuf)
            goto out_free_req;                                                       
        if (WARN_ON(out_len_max > PAGE_SIZE))
            goto out_free_all;
        memcpy(xbuf, payload, payload_len);

        // 设置加密操作的输入和输出
        sg_init_one(&src, xbuf, payload_len);                 
        sg_init_one(&dst, outbuf, out_len_max);

        akcipher_request_set_crypt(req, &src, &dst, payload_len, out_len_max);
        akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, tcrypt_complete, &result);

        // 执行加密操作
        err = wait_async_op(&result, crypto_akcipher_encrypt(req));
        if (err) {
            printk(KERN_ERR "Encryption failed\n");
            goto out_free_all;
        }
        else{
            printk(KERN_INFO "Encryption success\n");
        }

        // 更新 sk_buff 结构体长度
        skb_put(skb, out_len_max - payload_len);
        // 更新 ip 报文头中的总长度字段
        piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - payload_len);    // 更新IP报文长度字段
        // 更新 udp 报文头中的有效荷载数据长度字段
        switch(protocol) {
            case 17: 
                udphdr = (void *)piphdr + piphdr->ihl * 4; 
                udphdr->len = htons(ntohs(udphdr->len) + out_len_max - payload_len);    // 更新UDP报文长度字段
                break;
        }
        // tcp 报文头中没有存储有效荷载数据长度的字段，无需修改
        /*
        // 输出测试
        // 长度字段
        //printk("sk_length after skb_put: %d", skb->len);
        //printk("iph->tot_len after skb_put:: %d\n", ntohs(piphdr->tot_len));
        //printk("udph->len after skb_put:: %d\n", ntohs(udph->len));
        // 打印数据包头部信息
        printk(KERN_INFO "Data packet header information:\n");
        printk(KERN_INFO "Source MAC address: %pM\n", data);
        printk(KERN_INFO "Destination MAC address: %pM\n", data + 6);
        printk(KERN_INFO "Protocol: %04x\n", (data[12] << 8) + data[13]);
        */
        memcpy(payload, outbuf, out_len_max);             // 将数据从缓冲区输入到skb
        /*
        // 检查组织结构体的高低地址方式
        printk("skb->data address: %p\n", skb->data);
        printk("skb->tail address: %p\n", skb->tail);
        printk("skb IP header address: %p\n", skb->head);
        printk("piphdr address: %p\n", piphdr);
        */
        hexdump(outbuf, out_len_max);
    }
    // 对网络报文进行分块加解密处理        
    // 每次加密对 （out_len_max - 1） 长度的明文进行加密，得到的密文长度为 out_len_max
    else       
    {
        unsigned char *uncrypted_payload = payload;             // 指向待加解密有效载荷数据的起始位置
        unsigned int uncrypted_payload_len = payload_len;       // 记录剩余待加解密有效载荷数据的长度
        
        // 分配输出缓冲区
        outbuf = kzalloc(out_len_max, GFP_KERNEL);          
        if (!outbuf)
            goto out_free_req;                                                       
        if (WARN_ON(out_len_max > PAGE_SIZE))
            goto out_free_all;

        // 当未加密明文长度 > out_len_max - 1 时，循环执行加密操作
        // 每次加密对 (out_len_max - 1) 长度的明文进行加密，得到的密文长度为 out_len_max
        
        while(uncrypted_payload_len >= out_len_max)
        {
            memcpy(xbuf, uncrypted_payload, out_len_max - 1);
            
            // 设置加密操作的输入和输出
            sg_init_one(&src, xbuf, out_len_max - 1);                 
            sg_init_one(&dst, outbuf, out_len_max);

            akcipher_request_set_crypt(req, &src, &dst, out_len_max - 1, out_len_max);
            akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, tcrypt_complete, &result);

            // 执行加密操作
            err = wait_async_op(&result, crypto_akcipher_encrypt(req));
            if (err) {
                printk(KERN_ERR "Encryption failed\n");
                goto out_free_all;
            }
            else{
                printk(KERN_INFO "Encryption success\n");
            }
            // 将数据从缓冲区输入到 skb 中的有效荷载部分   
            memcpy(uncrypted_payload, outbuf, out_len_max);             
            // 将指针移动到下一块待加解密区域
            uncrypted_payload += out_len_max - 1;
            uncrypted_payload_len -= out_len_max - 1;
            // 调整sk_buff相关字段
            skb_put(skb, 1);
            piphdr->tot_len = htons(ntohs(piphdr->tot_len) + 1);
            switch(protocol) {
                case 17: 
                    udphdr = (void *)piphdr + piphdr->ihl * 4; 
                    udphdr->len = htons(ntohs(udphdr->len) + 1);
                    break;
            }
            hexdump(outbuf, out_len_max);
            kfree(outbuf);
        }
        // 当剩余未加密明文长度 < out_len_max 时，执行最后一次加密
        // 注：
        // 得到的密文长度为 out_len_max

        // 分配输出缓冲区
        outbuf = kzalloc(out_len_max, GFP_KERNEL);                          
        if (!outbuf)
            goto out_free_req;                                                       
        if (WARN_ON(out_len_max > PAGE_SIZE))
            goto out_free_all;
        memcpy(xbuf, uncrypted_payload, uncrypted_payload_len);
        // 设置加密操作的输入和输出
        sg_init_one(&src, xbuf, uncrypted_payload_len);                 
        sg_init_one(&dst, outbuf, out_len_max);

        akcipher_request_set_crypt(req, &src, &dst, uncrypted_payload_len, out_len_max);
        akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, tcrypt_complete, &result);

        // 执行加密操作
        err = wait_async_op(&result, crypto_akcipher_encrypt(req));
        if (err) {
            printk(KERN_ERR "Encryption failed\n");
            goto out_free_all;
        }
        else{
            printk(KERN_INFO "Encryption success\n");
        }
        // 存储输出密文长度
        out_len_max = dst.length;   
        // 调整sk_buff相关字段
        skb_put(skb, out_len_max - uncrypted_payload_len);
        piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - uncrypted_payload_len);  // 更新IP报文长度字段
        switch(protocol) {
            case 17: 
                udphdr = (void *)piphdr + piphdr->ihl * 4; 
                udphdr->len = htons(ntohs(udphdr->len) + out_len_max - uncrypted_payload_len);  // 更新UDP报文长度字段
                break;
        }
        // 将数据从缓冲区输入到 skb 中的有效荷载部分  
        memcpy(uncrypted_payload, outbuf, out_len_max);             
    }
out_free_all:
    kfree(outbuf);
out_free_req:
    akcipher_request_free(req);
out_free_tfm:
    crypto_free_akcipher(tfm);
out_free_xbuf:
    kfree(xbuf);
    return err;
}

/**
 * @brief 解密函数
 * 调用linux内核中的解密模块对指定报文数据进行RSA加解密,并同步更新sk_buff数据空间，修改其中的长度字段。
 * 
 * @param skb: 指向待解密报文的指针;
 * @param protocol 通信协议类型 (protocol == 6: TCP,  protcol == 17: UDP)；
 * @return int err：指示解密操作是否成功。正常返回err=1，如果发生错误返回，err=0；
 */
static int decrypt_data(struct sk_buff *skb, unsigned int protocol)
{
    printk("decrypt starting...");
    
    struct scatterlist src, dst;        //两个散列表，分别存储输入和输出数据
    struct akcipher_request *req;
    struct crypto_akcipher *tfm;
    struct tcrypt_result result;
    struct udphdr *udphdr;      //指向udp报文头部的指针
    struct tcphdr *tcphdr;      //指向tcp报文头部的指针
    unsigned char *word;                // 临时存储解密数据
    unsigned char *payload = NULL;      // 指向有效载荷数据的起始位置
    unsigned int payload_len = 0;       // 记录有效载荷数据的长度
    unsigned char *str = (unsigned char *)"exit";       // tcp通信的退出信息，用于跳过对报文流中的tcp退出信息加密
    int err = -ENOMEM;                                  // 错误码，用于错误检测和函数返回
    
    // 获取指向有效荷载数据的指针，有效荷载数据的长度
    // 指针payload：数据区域指针 +  ip 头长度 + tcp / udp 头长度
    // 长度payload_len：总长度 - ip 头长度 - tcp / udp 报文头长度
    // 
    // 注：
    // 对tcp报文，跳过对 exit 信息 和 接收方回复的 ACK 包加解密

    switch(protocol) {
        case 17: //UDP
            payload = ((unsigned char *)tmpskb->data + (piphdr->ihl * 4) + sizeof(struct udphdr));
            payload_len = skb->len - skb_transport_offset(skb) - sizeof(struct udphdr);
            break;
        case 6: //TCP
            tcphdr = tcp_hdr(skb);
            unsigned int tcphdr_len = tcphdr->doff * 4;
            payload = (unsigned char *)tcphdr + tcphdr_len;
            payload_len = skb->len - skb_transport_offset(skb) - tcphdr_len;
            // printk("tcphdr->doff: %d\n", tcphdr->doff);
            // printk("tcphdr->psh: %d\n", tcphdr->psh);
            // 对tcp的'exit'退出信息不解密
            if(!strncmp(str, payload, payload_len))
            {
                printk("This is a exit message");
                return err;
            }
            // 对接收方回复的ACK包不进行解密
            else if(payload_len == 0)                
            {
                printk("This is a ACK message");
                return err; 
            }
            break;
        default:
            return err;
    }
    // printk("payload_len: %d\n", payload_len);
    // 创建临时缓冲区，打印密文内容
    void *inbuf = NULL;     
    inbuf = kzalloc(payload_len, GFP_KERNEL);
    memcpy(inbuf, payload, payload_len);
    hexdump(inbuf, payload_len);
    kfree(inbuf);
    // 创建临时缓冲区，临时存储加解密操作的输入和输出数据
    void *xbuf = NULL;
    void *outbuf = NULL;
    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!xbuf)
        return err;
   
    // 创建密钥句柄
    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate key handle\n");
        goto out_free_xbuf;
    }
    // 分配请求对象
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "Failed to allocate request object\n");
        goto out_free_tfm;
    }
    // 设置RSA私钥
    err = crypto_akcipher_set_priv_key(crypto_akcipher_reqtfm(req), priv_key.data, priv_key.length);
    if (err) {
        printk(KERN_ERR "Failed to set RSA private key\n");
        goto out_free_req;
    }
    
    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);             //全局变量，rsa加解密可输出的最大长度
    
    // 关于加解密数据长度：
    // RSA加解密算法的明文必须小于密钥长度,加密时得到的密文等于密钥长度，长度不够会自动进行补零操作
    // 解密时对和公钥长度相等的密文进行解密

    // 对短报文直接进行加解密处理
    if(payload_len <= out_len_max)
    {
        outbuf = kzalloc(out_len_max, GFP_KERNEL);
        if (!outbuf)
            goto out_free_req;
        if (WARN_ON(out_len_max > PAGE_SIZE))
            goto out_free_all;
        memcpy(xbuf, payload, payload_len);
        
        // 设置解密操作的输入和输出
        sg_init_one(&src, xbuf, payload_len);
        sg_init_one(&dst, outbuf, out_len_max);

        akcipher_request_set_crypt(req, &src, &dst, payload_len, out_len_max);
        akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,tcrypt_complete, &result);

        // 执行解密操作
        err = wait_async_op(&result, crypto_akcipher_decrypt(req));
        if (err) {
            printk(KERN_ERR "Decryption failed\n");
            goto out_free_all;
        }
        else{
            out_len_max = dst.length;
            word = kzalloc(out_len_max, GFP_KERNEL);
            memcpy(word, outbuf, out_len_max);
            check_length(word, &out_len_max);           
            hexdump(word, out_len_max);
            printk(KERN_INFO "Decryption success\n");
            printk("the message is: %s\n", word);
        }
        // 修改 sk_buff 相应字段
        unsigned int new_skb_len = skb -> len + out_len_max - payload_len;
        skb_trim(skb, new_skb_len);             // 移动结构体tail指针改变内存空间大小，第二个参数是整个数据区域长度
        switch(protocol) {
            case 17: 
                udphdr = (void *)piphdr + piphdr->ihl * 4; 
                udphdr->len = htons(ntohs(udphdr->len) + out_len_max - payload_len);    // 更新 UDP 报文长度字段
                break;
        }
        piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - payload_len);    // 更新 IP 报文长度字段
        // 将数据从缓冲区输入到 skb 中的有效荷载部分
        memcpy(payload, outbuf, dst.length);    
        // 修正明文长度，去除空字符'\0'        
        check_length(payload, &dst.length);
        kfree(word);
    }
    // 对网络报文进行分块加解密处理 
    // 每次加密对小于等于 (out_len_max - 1) 长度的明文进行加密，得到的密文长度总为 out_len_max
    else if(payload_len > out_len_max)  
    {
        unsigned char *uncrypted_payload = payload;             // 指向待加解密有效载荷数据的起始位置
        unsigned int uncrypted_payload_len = payload_len;       // 记录剩余待加解密有效载荷数据的长度
        unsigned int crypted_payload_len = payload_len;         // 记录每次解密后的有效载荷数据长度   
        // 临时储存 payload 内容
        void *uncrypted_payload_buf = NULL;
        uncrypted_payload_buf = kzalloc(payload_len, GFP_KERNEL);
        memcpy(uncrypted_payload_buf, payload, payload_len);
        outbuf = kzalloc(out_len_max, GFP_KERNEL);          
        if (!outbuf)
            goto out_free_req;                                                       
        if (WARN_ON(out_len_max > PAGE_SIZE))
            goto out_free_all;
        while(uncrypted_payload_len > 0)
        {
            memcpy(xbuf, uncrypted_payload_buf, out_len_max);
            
            // 设置加密操作的输入和输出
            sg_init_one(&src, xbuf, out_len_max);                 
            sg_init_one(&dst, outbuf, out_len_max);

            akcipher_request_set_crypt(req, &src, &dst, out_len_max, out_len_max);
            akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, tcrypt_complete, &result);

            // 执行解密操作
            err = wait_async_op(&result, crypto_akcipher_encrypt(req));
            if (err) {
                printk(KERN_ERR "Encryption failed\n");
                goto out_free_all;
            }
            else{
                printk(KERN_INFO "Encryption success\n");
                check_length(outbuf, &dst.length);
            }
            // 将数据从缓冲区输入到 sk_buff 有效荷载部分
            memcpy(uncrypted_payload, outbuf, dst.length);             
            // 将指针移动到下一块待加解密区域
            uncrypted_payload += dst.length;
            uncrypted_payload_len -= out_len_max;
            uncrypted_payload_buf += out_len_max;
            crypted_payload_len -= out_len_max - dst.length;
            unsigned int new_skb_len = skb -> len + crypted_payload_len - payload_len;
            // 更新 sk_buff 相应字段
            skb_trim(skb, new_skb_len);         // 移动结构体tail指针改变内存空间大小，第二个参数是整个数据区域长度
            piphdr->tot_len = htons(ntohs(piphdr->tot_len) + crypted_payload_len - payload_len);    // 更新 IP 报文长度字段
            switch(protocol) {
                case 17: 
                    udphdr = (void *)piphdr + piphdr->ihl * 4; 
                    udphdr->len = htons(ntohs(udphdr->len) + crypted_payload_len - payload_len);    // 更新 UDP 报文长度字段
                    break;
            }
        }         
    }
    else    // 密文长度出错，数据完整性遭到破坏
    {
        printk(KERN_ERR "Data integrity is damaged\n");
	    return err;
    }
out_free_all:
    kfree(outbuf);
out_free_req:
    akcipher_request_free(req);
out_free_tfm:
    crypto_free_akcipher(tfm);
out_free_xbuf:
    kfree(xbuf);
    return err;
}

/**
 * @brief 检查端口匹配
 * 
 * @param srcport 待检查报文源端口
 * @param dstport 待检查报文目的端口
 * @return MATHCH -- 匹配 / NMATCH -- 不匹配
 */
int port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport) || ((controlled_srcport == dstport) && (controlled_dstport == srcport)))
			return MATCH;
		else
            //printk("Please input the correct port matching to communicating parties!\n");
            //printk("srcport: %d, dstport: %d\n", controlled_srcport, controlled_dstport);
			return NMATCH;
	}
    
	return NMATCH;
}

/**
 * @brief 检查IP地址匹配
 * 
 * @param saddr 待检查报文源地址
 * @param daddr 待检查报文目标地址
 * @return MATHCH -- 匹配 / NMATCH -- 不匹配
 */
int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if (((controlled_saddr == saddr) && (controlled_daddr == daddr)) || ((controlled_saddr == daddr) && (controlled_daddr == saddr)))
			return MATCH;
		else{
            //printk("Please input the correct ip address matching to communicating parties!\n");
            //printk("saddr: %d, daddr: %d\n", controlled_saddr, controlled_daddr);
			return NMATCH;
        }
	}

    return NMATCH;
}

/**
 * @brief 保持对ICMP报文的过滤规则
 * ICMP 协议通常用于在IP网络中发送错误报文和其他控制消息，不传输应用数据，故不设计 ICMP 加密通信
 * @return NF_DROP -- 过滤 ICMP 报文 / NF_ACCEPT -- 接受 ICMP 报文
 */
int icmp_check(void){
    struct icmphdr *picmphdr;   // 获取 ICMP 报文头
    picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));
    
	if (picmphdr->type == 0){	// 远程主机向发出ping请求报文的客户端所回复的ping应答报文
			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
	}
	if (picmphdr->type == 8){	// 客户端向远程主机发出的ping请求报文
			if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
	}
    return NF_ACCEPT;
}

/**
 * @brief 检查 TCP 报文并进行加解密
 * 
 * @param skb 待检查的网络报文指针
 * @param flag 1-- 加密 / 0 -- 解密
 * @return NF_ACCEPT -- 接受 TCP 报文
 */
int tcp_check(struct sk_buff *skb, int flag){
    struct tcphdr *ptcphdr;
    ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));

	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) || (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	
        if(flag){
            // 加密
            printk("A TCP packet is encrypted! \n");
            encrypt_data(skb, 6);
        }
        else{
            // 解密
            printk("A TCP packet is decrypted! \n");
            decrypt_data(skb, 6);
        }
        recalculate_tcp_checksum(skb);
	}    

    return NF_ACCEPT;
}

/**
 * @brief 检查 UDP 报文并进行加解密
 * 
 * @param skb 待检查的网络报文指针
 * @param flag 1-- 加密 / 0 -- 解密
 * @return NF_ACCEPT -- 接受 TCP 报文
 */
int udp_check(struct sk_buff *skb, int flag){
	struct udphdr *pudphdr;
    pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
    
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) || (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
        if(flag){
            // 加密
            printk("A UDP packet is encrypted! \n");
            encrypt_data(skb, 17);
        }
        else{
            // 解密
            printk("A UDP packet is decrypted! \n");
            decrypt_data(skb, 17);
        } 
        // 更新UDP校验和
        recalculate_udp_checksum(skb);
	}

    return NF_ACCEPT;
}

/**
 * @brief 进站钩子函数，处理接受的网络数据包
 * 
 * @param priv 
 * @param skb 
 * @param state 
 * @return NF_DROP -- 过滤报文 / NF_ACCEPT -- 接受报文
 */
static unsigned int in_hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    if (enable_flag == 0)       //检查控制规则启用标志
	    return NF_ACCEPT;          
    
    // 解密数据
    tmpskb = skb;
    piphdr = ip_hdr(tmpskb);
    
   	if(piphdr->protocol != controlled_protocol)
      		return NF_ACCEPT;
   
   if (piphdr->protocol  == 1)  //ICMP packet
		return icmp_check();
	else if (piphdr->protocol  == 6) //TCP packet
		return tcp_check(skb, 0);
	else if (piphdr->protocol  == 17) //UDP packet
		return udp_check(skb, 0);
	else
	{
		printk("Unkonwn type's packet! \n");
		return NF_ACCEPT;
	}

    return NF_ACCEPT;
}

/**
 * @brief 出站钩子函数，处理发送的网络数据包
 * 
 * @param priv 指向私有数据的指针，用于在钩子函数中共享数据。
 * @param skb 指向Netfilter正在处理报文缓冲区的指针
 * @param state 指向 nf_hook_state 结构的指针，这个结构包含了钩子函数执行时的相关状态信息，如网络接口、协议等
 * @return NF_DROP -- 过滤报文 / NF_ACCEPT -- 接受报文
 */
static unsigned int out_hook_func(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
	if (enable_flag == 0)
		return NF_ACCEPT;    
    // 加密数据
    tmpskb = skb;               // 获得报文缓冲区的地址指针
    piphdr = ip_hdr(tmpskb);    // 获得IP报文的头部
    
   	if(piphdr->protocol != controlled_protocol)     // 对不合控制规则的报文，直接放行
      	return NF_ACCEPT;
   
   if (piphdr->protocol  == 1)  //ICMP packet
		return icmp_check();
	else if (piphdr->protocol  == 6) //TCP packet
		return tcp_check(skb, 1);
	else if (piphdr->protocol  == 17) //UDP packet
		return udp_check(skb, 1);
	else
	{
		printk("Unkonwn type's packet! \n");
		return NF_ACCEPT;
	}

    return NF_ACCEPT;
}


/**
 * @brief 从用户空间写入指令信息
 * 通过调用函数copy_from_user()，将来自应用层空间的缓冲区内容（即控制规则信息，由参数buf传递进该函数）复制到内核层空间的缓冲区（一组全局变量）中
 * 
 * @param fd 文件描述符
 * @param buf 拟写入内容的缓冲区指针
 * @param len 拟写入长度
 * @param ppos 文件的偏移量
 * @return ssize_t 
 */
static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];      // 用于保存所写入内容的内核空间缓冲区
	char *pchar;                // 临时缓冲区指针
	pchar = controlinfo;

    if (len == 0){                      // 如果写入的内容长度为0,表示关闭该防火墙的检查控制功能
		enable_flag = 0;                // 设置防火墙关闭标志
		return len;                     
	}
    // 调用函数copy_from_user()将规则配置程序传入的用户配置信息(即要控制的信息，如IP地址、端口等)复制到内核空间缓存区
	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);

	enable_flag = 1;                    // 设置防火墙启用标志
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", 
            controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);
	return len;
}

// 文件操作结构体
struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};

// 内核模块初始化函数
static int __init test_init(void)
{
    printk("starting...");
    printk("to run the crypto module, please configure like this:\n");
    printk("sudo ./configure -p tcp/udp -x ip -y ip, the ip sequence is variable, or\n");
    printk("sudo ./configure -p tcp/udp -m port -n port, the port sequence is variable\n");
    int ret;
    int bytes_read;

    // 分配内存用于存储公钥和私钥
    pub_key.data = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    priv_key.data = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    if (!pub_key.data) {
        printk(KERN_ALERT "Failed to allocate memory\n");
        return -ENOMEM;
    }
    if (!priv_key.data) {
        printk(KERN_ALERT "Failed to allocate memory\n");
        kfree(pub_key.data);
        return -ENOMEM;
    }
    // 读取公钥和私钥文件内容
    bytes_read = read_file("other_side_public_key", 0);
    if (bytes_read < 0) {
        kfree(pub_key.data);
        kfree(priv_key.data);
        return bytes_read;
    }
    bytes_read = read_file("my_own_private_key", 1);
    if (bytes_read < 0) {
        kfree(pub_key.data);
        kfree(priv_key.data);
        return bytes_read;
    }
    printk("key accessed!");

    // 初始化钩子函数
    nfho_in.hook = in_hook_func,
    nfho_in.hooknum = NF_INET_PRE_ROUTING,
    nfho_in.pf = PF_INET,
    nfho_in.priority = NF_IP_PRI_FIRST,

    nfho_out.hook = out_hook_func,
    nfho_out.hooknum = NF_INET_POST_ROUTING,
    nfho_out.pf = PF_INET,
    nfho_out.priority = NF_IP_PRI_FIRST,
    
    // 注册钩子函数
    nf_register_net_hook(&init_net, &nfho_in);
    nf_register_net_hook(&init_net, &nfho_out);
    // 向系统注册设备节点文件
    ret = register_chrdev(124, "/dev/controlinfo", &fops);
    if (ret != 0) 
        printk("Can't register device file! \n"); 
    return 0;
}

// 内核模块清理函数
static void __exit test_exit(void)
{
    // 注销钩子函数
    nf_unregister_net_hook(&init_net, &nfho_in);
    nf_unregister_net_hook(&init_net, &nfho_out);
    // 向系统注销设备节点文件
    unregister_chrdev(124, "controlinfo");
    // 释放密钥内存
    kfree(pub_key.data);
    kfree(priv_key.data);
    printk("CleanUp\n");
}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");

