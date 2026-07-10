# Anti-Probe Firewall

**ابزار پیشرفته بلاک کردن Active Probing، Port Scanning و SYN Flood** با استفاده از **nftables**

نسخه ۲.۰ - کاملاً قابل تنظیم

---

## ویژگی‌ها

- تشخیص و بلاک خودکار آی‌پی‌های مشکوک
- Whitelist دائمی (برای سرورهای ایرانی، پنل‌ها و ...)
- لیمیت قابل تنظیم از طریق آرگومان
- مدیریت آسان blacklist و whitelist
- سازگار با SSH (آی‌پی فعلی شما به صورت خودکار whitelist می‌شود)
- نصب و uninstall بسیار ساده

---

## نصب

```bash
chmod +x setup_anti_probe.sh
sudo ./setup_anti_probe.sh
```


---------

نصب با تنظیمات پیش‌فرض

```
sudo ./setup_anti_probe.sh
```

نصب با لیمیت دلخواه



# حساس‌تر (۱۰ پکت در ثانیه)
```
sudo ./setup_anti_probe.sh --rate 10 --burst 20
```

# خیلی حساس
```
sudo ./setup_anti_probe.sh --rate 7 --burst 15
```

# برای سرورهای پرترافیک

```
sudo ./setup_anti_probe.sh --rate 25 --burst 40
```

-----


# مدیریت Whitelist:


# اضافه کردن آی‌پی مهم
```
sudo ./setup_anti_probe.sh -a 5.202.10.50     # ایرانسل
sudo ./setup_anti_probe.sh -a 79.127.127.10   # همراه اول
sudo ./setup_anti_probe.sh -a YOUR_IP         # آی‌پی خودتان
```


# مدیریت Blacklist:
```
sudo ./setup_anti_probe.sh -b 203.0.113.55    # بلاک دستی
sudo ./setup_anti_probe.sh -s                 # چک کردن لیست بلاک
sudo ./setup_anti_probe.sh -u 203.0.113.55    # آنبن
```

# غیرفعال‌سازی:

```
sudo ./setup_anti_probe.sh -d        # غیرفعال موقت
sudo ./setup_anti_probe.sh -U        # حذف کامل
```


## Complete Command List

| Argument | Description | Example |
|:---------|:------------|:--------|
| `-h`, `--help` | Display the complete help menu | `sudo ./setup_anti_probe.sh -h` |
| `-s`, `--status` | Show blocked IP addresses and their remaining ban time | `sudo ./setup_anti_probe.sh -s` |
| `-w`, `--whitelist` | Display the whitelist | `sudo ./setup_anti_probe.sh -w` |
| `-l`, `--list-all` | Display all active nftables rules | `sudo ./setup_anti_probe.sh -l` |
| `-a`, `--allow <IP>` | Add an IP address to the permanent whitelist | `sudo ./setup_anti_probe.sh -a 185.123.45.67` |
| `-r`, `--remove <IP>` | Remove an IP address from the whitelist | `sudo ./setup_anti_probe.sh -r 185.123.45.67` |
| `-b`, `--ban <IP>` | Manually ban an IP address for 24 hours | `sudo ./setup_anti_probe.sh -b 198.51.100.23` |
| `-u`, `--unban <IP>` | Remove an IP address from the blacklist (Unban) | `sudo ./setup_anti_probe.sh -u 198.51.100.23` |
| `-d`, `--disable` | Temporarily disable the firewall by flushing all rules | `sudo ./setup_anti_probe.sh -d` |
| `-U`, `--uninstall` | Completely uninstall the firewall and remove its configuration | `sudo ./setup_anti_probe.sh -U` |
| `--rate <number>` | Set the SYN packet rate limit (packets per second) | `sudo ./setup_anti_probe.sh --rate 10` |
| `--burst <number>` | Set the allowed SYN burst size | `sudo ./setup_anti_probe.sh --rate 10 --burst 20` |
