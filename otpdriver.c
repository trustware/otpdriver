#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>   /* printk() */
#include <linux/slab.h>     /* kmalloc() */
#include <linux/fs.h>       /* everything... */
#include <linux/errno.h>    /* error codes */
#include <linux/types.h>    /* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>    /* O_ACCMODE */
#include <asm/uaccess.h>    /* copy_from/to_user */
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/sha.h>

#include "base32.h"

MODULE_LICENSE("Dual BSD/GPL");

int otp_open(struct inode *inode, struct file *filp);
int otp_release(struct inode *inode, struct file *filp);
ssize_t otp_read(struct file *filp, char *buf, size_t count, loff_t *f_pos);
void otp_exit(void);
int otp_init(void);

struct file_operations otp_fops =
{
    .read = otp_read,
    .open = otp_open,
    .release = otp_release
};

module_init(otp_init);
module_exit(otp_exit);

int otp_major = 60;

int otp_init(void) {
    int result;
    result = register_chrdev(otp_major, "otp", &otp_fops);
    if (result < 0) {
        printk("<1>otp: cannot obtain major number %d\n", otp_major);
        return result;
    }

    return 0;
}

void otp_exit(void) {
    unregister_chrdev(otp_major, "otp");
}

int otp_open(struct inode *inode, struct file *filp) {
    return 0;
}

int otp_release(struct inode *inode, struct file *filp) {
      return 0;
}

ssize_t otp_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    unsigned char base32_key[] = "";
    size_t base32_key_len = strlen(base32_key);

    size_t out_size = 7;
    unsigned char out[out_size];

    struct scatterlist sg;
    struct hash_desc desc;

    size_t key_len = base32_key_len;
    unsigned char key[key_len];

    unsigned char hashtext[SHA1_DIGEST_SIZE];

    unsigned long long time;
    unsigned int totp;
    unsigned int offset;
    unsigned char time_array[8];


    if (count < out_size) {
        return -EINVAL;
    }

    if (*f_pos != 0) {
        return 0;
    }

    key_len = base32_decode(base32_key, key, key_len);

    time = get_seconds() / 30;
    time_array[0] = (time >> 56) & 0xFF;
    time_array[1] = (time >> 48) & 0xFF;
    time_array[2] = (time >> 40) & 0xFF;
    time_array[3] = (time >> 32) & 0xFF;
    time_array[4] = (time >> 24) & 0xFF;
    time_array[5] = (time >> 16) & 0xFF;
    time_array[6] = (time >> 8) & 0xFF;
    time_array[7] = time & 0xFF;

    sg_init_one(&sg, time_array, 8);
    desc.flags = 0;
    desc.tfm = crypto_alloc_hash("hmac(sha1)", 0, CRYPTO_ALG_ASYNC);

    crypto_hash_init(&desc);
    crypto_hash_setkey(desc.tfm, key, key_len);
    crypto_hash_digest(&desc, &sg, sg.length, hashtext);

    offset = hashtext[SHA1_DIGEST_SIZE - 1] & 0xF;
    totp = hashtext[offset] << 24;
    totp |= hashtext[offset + 1] << 16;
    totp |= hashtext[offset + 2] << 8;
    totp |= hashtext[offset + 3];

    totp &= 0x7fffffff;
    totp = totp % 1000000;

    snprintf(out, out_size, "%06d", totp);

    crypto_free_hash(desc.tfm);

    if (copy_to_user(buf, out, out_size)) {
        return -EINVAL;
    }

    *f_pos = out_size;

    return out_size;
}
