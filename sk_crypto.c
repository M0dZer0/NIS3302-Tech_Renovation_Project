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

#define MAX_BUFFER_SIZE 1024


#define MATCH	1
#define NMATCH	0

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
int enable_flag = 0;
struct sk_buff *tmpskb;
struct iphdr *piphdr;
struct nf_hook_ops nfho_in;
struct nf_hook_ops nfho_out;

struct tcrypt_result
{
    struct completion completion;
    int err;
};
struct my_key {
    unsigned char *data;
    int length;
};

struct my_key priv_key;
struct my_key pub_key;
unsigned int out_len_max = 0;






// 计算TCP头部的总长度
unsigned int calculate_tcp_header_length(struct sk_buff *skb, const struct tcphdr *th)
{
    unsigned int header_length = 20;  // 固定部分的长度为20字节

    // 检查是否存在选项字段
    if (th->doff > 5) {
        unsigned int options_length = tcp_optlen(skb);  // 计算选项字段的长度
        header_length += options_length;  // 将选项字段的长度添加到总长度中
    }

    return header_length;
}
void update_tcp_header(struct sk_buff *skb) {
    struct tcphdr *tcph;
    struct iphdr *iph;

    // 获取 TCP 头部和 IP 头部指针
    tcph = tcp_hdr(skb);
    iph = ip_hdr(skb);

    // 更新 TCP 头部的长度字段
    tcph->doff = calculate_tcp_header_length(skb, tcph);
    // 重新计算 TCP 校验和
    iph->check = 0;
    iph->check = ip_fast_csum(iph, iph->ihl);
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4),IPPROTO_TCP,csum_partial(tcph, (ntohs(iph ->tot_len)-iph->ihl*4), 0));

}

/*

可能需要修改的信息
- ip头部信息中的tot_len字段 （在哪里修改捏）
- udp/tcp头部信息中的len字段
- skb->ip_summed
- skb->csum
- iph->check
- udph->check

*/


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
    udph->check=csum_tcpudp_magic(iph->saddr,iph->daddr,(ntohs(iph ->tot_len)-iph->ihl*4), IPPROTO_UDP,csum_partial(udph, (ntohs(iph ->tot_len)-iph->ihl*4), 0));
   
}


// 读取加解密文件内容
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
    void *outbuf = NULL;
    outbuf = kzalloc(len, GFP_KERNEL);                             
    if (!outbuf)
        kfree(outbuf);                                                    
    if (WARN_ON(out_len_max > PAGE_SIZE))
        kfree(outbuf);  
    memcpy(outbuf, buf, len);
    while (len--)
        printk("%02x", *buf++);
    printk("\n");
    kfree(outbuf);
}

static void check_length(unsigned char *buf, unsigned int *len)
{
    int i = 0;
    while (buf[i] == '\0') {
        i++;
        (*len)--;
    }
    memmove(buf, buf + i, *len); // 移动字符串，将字符串前面的空格去掉，防止内存泄漏
    buf[*len] = '\0'; // 添加字符串结束符
}

static void tcrypt_complete(struct crypto_async_request *req, int err)
{
    struct tcrypt_result *res = req->data;
    if (err == -EINPROGRESS)
        return;
    res->err = err;
    complete(&res->completion);
}
static int wait_async_op(struct tcrypt_result *tr, int ret)
{
    if (ret == -EINPROGRESS || ret == -EBUSY)
    {
        wait_for_completion(&tr->completion);
        reinit_completion(&tr->completion);
        ret = tr->err;
    }
    return ret;
}



//加密函数
static int encrypt_data(struct sk_buff *skb, unsigned int protocol)
{
    printk("encrypt starting...");
    
    struct scatterlist src, dst;    //两个散列表，分别存储输入和输出数据
    struct akcipher_request *req;
    struct crypto_akcipher *tfm;
    struct tcrypt_result result;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    unsigned char *payload = NULL;      // 指向有效载荷数据的起始位置
    unsigned int payload_len = 0;       // 记录有效载荷数据的长度

    int err = -ENOMEM;              //错误码
    
    // 获取数据指针和长度
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
            break;
        default:
            return err;
    }
    // test point
    //printk("input: \n");
    hexdump(payload, payload_len);      //输入 + 换行符
    //printk("\n");

    printk("piphdr->tot_len: %d", piphdr->tot_len);
    // 创建缓冲区，存储输入和输出数据
    void *xbuf = NULL;
    void *outbuf = NULL;
    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);                                  //out_free_xbuf
    if (!xbuf)
        return err;
    
    // 创建密钥句柄
    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);             //out_free_tfm
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate key handle\n");
        goto out_free_xbuf;
    }

    // 分配请求对象
    req = akcipher_request_alloc(tfm, GFP_KERNEL);                          //out_free_req
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
    out_len_max = crypto_akcipher_maxsize(tfm);                             //全局变量，可密文最大长度
    outbuf = kzalloc(out_len_max, GFP_KERNEL);                              //out_free_all
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
    
    out_len_max = dst.length;
    // 检查变量: 
    // struct udphdr *udphdr;
    // udphdr = (void *)piphdr + piphdr->ihl * 4;
    /*
    printk("iph->tot_len before skb_put:: %d\n", ntohs(piphdr->tot_len));
    printk("udph->len before skb_put:: %d\n", ntohs(udph->len));
    printk("sk_length before skb_put: %d", skb->len);
    */
    skb_put(skb, out_len_max - payload_len);
    piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - payload_len);

    switch(protocol) {
        case 17: 
            udphdr = (void *)piphdr + piphdr->ihl * 4; 
            udphdr->len = htons(ntohs(udphdr->len) + out_len_max - payload_len);
            break;
    }
    // piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - payload_len);
    // udphdr->len = htons(ntohs(udphdr->len) + out_len_max - payload_len);
    /*
    printk("sk_length after skb_put: %d", skb->len);
    printk("iph->tot_len after skb_put:: %d\n", ntohs(piphdr->tot_len));
    printk("udph->len after skb_put:: %d\n", ntohs(udph->len));
    */
    
    //test skb->head
    unsigned char *data = skb->head;
    int data_len = skb->len;
    /*
    // 打印数据包头部信息
    printk(KERN_INFO "Data packet header information:\n");
    printk(KERN_INFO "Source MAC address: %pM\n", data);
    printk(KERN_INFO "Destination MAC address: %pM\n", data + 6);
    printk(KERN_INFO "Protocol: %04x\n", (data[12] << 8) + data[13]);

    // 打印数据包有效载荷
    printk(KERN_INFO "Data packet payload:\n");
    int i;
    for(i = 14; i < data_len; i++) {
        printk(KERN_INFO "%02x ", data[i]);
        if((i+1) % 16 == 0) {
            printk(KERN_INFO "\n");
        }
    }
    printk(KERN_INFO "\n");
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



// 解密函数
static int decrypt_data(struct sk_buff *skb, unsigned int protocol)
{
    printk("decrypt starting...");
    
    struct scatterlist src, dst;                        //两个散列表，分别存储输入和输出数据
    struct akcipher_request *req;
    struct crypto_akcipher *tfm;
    struct tcrypt_result result;
    unsigned char *word;
    struct udphdr *udphdr;
    struct tcphdr *tcphdr;
    unsigned char *payload = NULL;      // 指向有效载荷数据的起始位置
    unsigned int payload_len = 0;       // 记录有效载荷数据的长度


    int err = -ENOMEM;

    // 获取数据指针和长度
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
        default:
            return err;
    }
    
    
    
    // test point
    //printk("input: \n");
    hexdump(payload, payload_len);      //输入 + 换行符
    //printk("\n");


    // 创建缓冲区，临时存储输入和输出数据
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
    
    out_len_max = crypto_akcipher_maxsize(tfm);             //全局变量，可密文最大长度
    outbuf = kzalloc(out_len_max, GFP_KERNEL);
    if (!outbuf)
        goto out_free_req;
    if (WARN_ON(out_len_max > PAGE_SIZE))
        goto out_free_all;
    
    memcpy(xbuf, payload, payload_len);
    // 设置解密操作的输入和输出
    sg_init_one(&src, xbuf, payload_len);                   //edit
    sg_init_one(&dst, outbuf, out_len_max);


    akcipher_request_set_crypt(req, &src, &dst, payload_len, out_len_max);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  tcrypt_complete, &result);

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
        check_length(word, &out_len_max);             // outbuf是void *类型指针
        hexdump(word, out_len_max);
        printk(KERN_INFO "Decryption success\n");
        printk("the message is: %s\n", word);
    }

    // 修改skb
    unsigned int new_skb_len = skb -> len + out_len_max - payload_len;
    skb_trim(skb, new_skb_len);                         // edit: 第二个参数是整个数据区域长度


    switch(protocol) {
        case 17: 
            udphdr = (void *)piphdr + piphdr->ihl * 4; 
            udphdr->len = htons(ntohs(udphdr->len) + out_len_max - payload_len);
            break;
    }
    piphdr->tot_len = htons(ntohs(piphdr->tot_len) + out_len_max - payload_len);
    memcpy(payload, outbuf, dst.length);             // 将数据从缓冲区输入到skb->data
    check_length(payload, &dst.length);             // outbuf是void *类型指针
    hexdump(payload, dst.length);
    kfree(word);
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

int icmp_check(void){
	struct icmphdr *picmphdr;
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
        update_tcp_header(skb);
	}    

      return NF_ACCEPT;
}

int udp_check(struct sk_buff *skb, int flag){
	struct udphdr *pudphdr;
    pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));

    /*
    //检查udp头部
    printk("the uncrypted UDP");
    printk("UDP protocol: %d", piphdr -> protocol);
    printk("UDP destination: %d", piphdr -> daddr);
    printk("UDP por: %d", pudphdr -> dest);
    */
    
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

    /*
    //检查udp头部
    printk("the crypted UDP");
    printk("UDP protocol: %d", piphdr -> protocol);
    printk("UDP destination: %d", piphdr -> daddr);
    printk("UDP por: %d", pudphdr -> dest);
    */

    return NF_ACCEPT;
}


static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    if (enable_flag == 0)
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

static unsigned int out_hook_func(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
	if (enable_flag == 0)
		return NF_ACCEPT;    
    // 加密数据
    tmpskb = skb;
    piphdr = ip_hdr(tmpskb);
    
   	if(piphdr->protocol != controlled_protocol)
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
static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;

	pchar = controlinfo;

	if (len == 0){
		enable_flag = 0;
		return len;
	}

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

	enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);
	return len;
}

struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};

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
    bytes_read = read_file("pub_key_file", 0);
    if (bytes_read < 0) {
        kfree(pub_key.data);
        kfree(priv_key.data);
        return bytes_read;
    }

    bytes_read = read_file("pri_key_file", 1);
    if (bytes_read < 0) {
        kfree(pub_key.data);
        kfree(priv_key.data);
        return bytes_read;
    }

    printk("key accessed!");

    nfho_in.hook = hook_func,
    nfho_in.hooknum = NF_INET_PRE_ROUTING,
    nfho_in.pf = PF_INET,
    nfho_in.priority = NF_IP_PRI_FIRST,

    nfho_out.hook = out_hook_func,
    nfho_out.hooknum =NF_INET_POST_ROUTING,
    nfho_out.pf = PF_INET,
    nfho_out.priority = NF_IP_PRI_FIRST,
    
    
    // 初始化钩子函数
    nf_register_net_hook(&init_net,&nfho_in);
    nf_register_net_hook(&init_net,&nfho_out);
    ret = register_chrdev(124, "/dev/controlinfo", &fops);
    if (ret != 0) printk("Can't register device file! \n");
    return 0;
}

static void __exit test_exit(void)
{
    
    nf_unregister_net_hook(&init_net,&nfho_in);
    nf_unregister_net_hook(&init_net,&nfho_out);
    unregister_chrdev(124, "controlinfo");
    kfree(pub_key.data);
    kfree(priv_key.data);
    printk("CleanUp\n");
}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");

