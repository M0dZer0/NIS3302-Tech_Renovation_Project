#include <linux/module.h>
#include <linux/kernel.h>
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
#define MAX_BUFFER_SIZE 1024
struct my_key
{
    unsigned char *data;
    int length;
};
struct my_key priv_key;
struct my_key pub_key;
static int read_file(const char *filename, int flag)
{
    struct file *file;
    mm_segment_t oldfs;
    int bytes_read = 0;
    // 打开文件
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        printk(KERN_ALERT "Failed to open file\n");
        return -1;
    }
    // 切换到内核空间的地址空间
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    if (flag == 0)
    {
        // 读取文件内容
        bytes_read = vfs_read(file, pub_key.data, MAX_BUFFER_SIZE, &file->f_pos); // vfs_read函数的四个参数分别是文件指针，缓冲区指针，缓冲区大小，文件指针的偏移量
        pub_key.length = bytes_read;
    }
    else
    {
        bytes_read = vfs_read(file, priv_key.data, MAX_BUFFER_SIZE, &file->f_pos); // vfs_read函数的四个参数分别是文件指针，缓冲区指针，缓冲区大小，文件指针的偏移量
        priv_key.length = bytes_read;
    }
    // 恢复地址空间
    set_fs(oldfs);
    // 关闭文件
    filp_close(file, NULL);
    return bytes_read;
}
const char *msg = "lalalala";
const int msg_len = 8;
char *crypted = NULL;
int crypted_len = 0;
struct tcrypt_result
{
    struct completion completion;
    int err;
};
struct akcipher_testvec
{
    unsigned char *key;
    unsigned char *msg;
    unsigned int key_size;
    unsigned int msg_size;
};
static inline void hexdump(unsigned char *buf, unsigned int len)
{
    while (len--)
        printk("%02x", *buf++);
    printk("\n");
}

static void check_length(unsigned char *buf, unsigned int *len)
{
    int i = 0;
    while (buf[i] == '\0')
    {
        i++;
        (*len)--;
    }
    memmove(buf, buf + i, *len); // 移动字符串，将字符串前面的空格去掉，防止内存泄漏
    buf[*len] = '\0';            // 添加字符串结束符
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
static int uf_akcrypto(struct crypto_akcipher *tfm,
                       void *data, int datalen, int phase)
{
    void *xbuf = NULL;
    struct akcipher_request *req;
    void *outbuf = NULL;
    struct tcrypt_result result;
    unsigned int out_len_max = 0;
    struct scatterlist src, dst;
    int err = -ENOMEM;
    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!xbuf)
        return err;
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
        goto free_xbuf;
    init_completion(&result.completion);
    if (phase) // test
        err = crypto_akcipher_set_pub_key(tfm, pub_key.data, pub_key.length);
    else
        err = crypto_akcipher_set_priv_key(tfm, priv_key.data, priv_key.length);
    if (err)
    {
        printk("set key error! %d,,,,,%d\n", err, phase);
        goto free_req;
    }
    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);
    outbuf = kzalloc(out_len_max, GFP_KERNEL);
    if (!outbuf)
        goto free_req;
    if (WARN_ON(datalen > PAGE_SIZE))
        goto free_all;
    memcpy(xbuf, data, datalen);
    sg_init_one(&src, xbuf, datalen);
    sg_init_one(&dst, outbuf, out_len_max);
    akcipher_request_set_crypt(req, &src, &dst, datalen, out_len_max);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  tcrypt_complete, &result);
    if (phase)
    {
        err = wait_async_op(&result, crypto_akcipher_encrypt(req));
        if (err)
        {
            pr_err("alg: akcipher: encrypt test failed. err %d\n", err);
            goto free_all;
        }
        else
        {
            memcpy(crypted, outbuf, out_len_max);
            crypted_len = out_len_max;
            printk("<1>encryption success\n");
            printk("length: %d\n", out_len_max);
            hexdump(crypted, crypted_len);
        }
    }
    else
    {
        err = wait_async_op(&result, crypto_akcipher_decrypt(req));
        if (err)
        {
            pr_err("alg: akcipher: decrypt test failed. err %d\n", err);
            goto free_all;
        }
        else
        {
            printk("<1>decryption success");
            check_length(outbuf, &out_len_max);
            printk("length: %d\n", out_len_max);
            hexdump(outbuf, out_len_max);
            printk("the message is  %s\n", outbuf);
        }
    }
free_all:
    kfree(outbuf);
free_req:
    akcipher_request_free(req);
free_xbuf:
    kfree(xbuf);
    return err;
}
static int userfaultfd_akcrypto(void *data, int datalen, int phase)
{
    struct crypto_akcipher *tfm;
    int err = 0;
    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
    if (IS_ERR(tfm))
    {
        pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    err = uf_akcrypto(tfm, data, datalen, phase);
    crypto_free_akcipher(tfm);
    return err;
}
static int __init test_init(void)
{
    int bytes_read;
    pub_key.data = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    priv_key.data = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    crypted = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!crypted)
    {
        printk("crypted kmalloc error\n");
        return -1;
    }
    if (!pub_key.data)
    {
        printk(KERN_ALERT "Failed to allocate memory\n");
        return -ENOMEM;
    }
    if (!priv_key.data)
    {
        printk(KERN_ALERT "Failed to allocate memory\n");
        return -ENOMEM;
    }
    // 读取文件内容
    bytes_read = read_file("pub_key_file", 0);
    if (bytes_read < 0)
    {
        kfree(pub_key.data);
        return bytes_read;
    }
    bytes_read = read_file("pri_key_file", 1);
    if (bytes_read < 0)
    {
        kfree(priv_key.data);
        return bytes_read;
    }
    crypted = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!crypted)
    {
        printk("crypted kmalloc error\n");
        return -1;
    }
    printk("pub_key length: %d\n", pub_key.length);
    printk("priv_key length: %d\n", priv_key.length);
    userfaultfd_akcrypto(msg, msg_len, 1);
    userfaultfd_akcrypto(crypted, crypted_len, 0);
    kfree(crypted);
    return 0;
}
static void __exit test_exit(void)
{
    kfree(pub_key.data);
    kfree(priv_key.data);
}
module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");