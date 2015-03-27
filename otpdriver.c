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
    unsigned long long otp = 0xDEADBEEFD15EA5E5;
    int char_size = sizeof(otp) * 2;
    char hexotp[char_size + 1];

    if (count < char_size) {
        return -EINVAL;
    }

    if (*f_pos != 0) {
        return 0;
    }

    snprintf(hexotp, char_size + 1, "%llX", otp);

    if (copy_to_user(buf, hexotp, char_size)) {
        return -EINVAL;
    }

    *f_pos = char_size;

    return char_size;
}
