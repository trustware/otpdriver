# otpdriver

To install:
```
make
sudo insmod otp.ko
sudo mknod /dev/otp c 60 0
```

To remove:
```
sudo rmmod otp
sudo rm /dev/otp
```
