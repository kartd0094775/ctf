ntucsie_computer_security_final_ctf_writeup
===
* 組別：ABC告嘎低
* 組員：R06922084
* 組員：R06922086
* 組員：B05902055
* 組員：R06922078 

### tele
這題總共要過三關： lock0, lock1, lock2
前兩關做 MitM attack，開兩個 client 互傳就可以過了
lock2 就是 brute-force 硬猜，因為是用 AES_OFB 的加密方式
![](https://i.imgur.com/84Q2aAW.png)
以上圖來說，最後一個 ciphertext 的解密一定是 $E^3(IV)\oplus C[3] = M[3]$
那就做 $C[3]\oplus 13$ 直到通過 lock2

flag: `flag{=*-te.te-tele.te.--te.te-tele.te-*=}`
script: https://github.com/kartd0094775/ctf/blob/master/cs/final/tele/tele.py

### welcome
這題將 flag 切成兩半，flag 的形式 `flag{xxxxx}`
前半用當時的 timestamp 當做 seed，然後 randomrange(256) 做 xor
後半用則用一個 common word 當做 seed，然後 randomrange(256) xor
之後再將兩個加密完後的一半的 flag 接起來，做 base64encode 產生 output file。

我們按照步驟解回來，flag 總長度為 54。
再來就是前半 flag 的開頭五個字為 `flag{`
逆推前五個 random number 為 [161, 61, 12, 90, 178]
然後找到 seed timestamp: 1547167075

接著是後半 flag 的最後一個字為 `}`
逆推最後一個 random number 為 114
從助教新增的提示去從 rockyou.txt 找常用字
最後找到 seed common word: punzalan

flag: `flag{\|/-3b4dabaf1e772-H4pPy_N3w_y3aR-ccce3295f562\|/}`

script: https://github.com/kartd0094775/ctf/blob/master/cs/final/welcome/welcome.py


### GhostShell v1
直接執行程式發現它print了"FLAG{V\QWk1]OB#F#BC#OU\1DUm}"，
這大概是真的flag經過一些處理的產物。用IDA看它發現不能反編譯，
就想這大概和HW3一樣。所以就用x64dbg把不必要的指令用nop取代，
但它還有一些變化，例如用怪怪的方式call function，這時候就把它改成正常call function。
最後再用IDA看發現它把"V\QWk1]OB#F#BC#OU\1Dum"的每個字元都和0x10 xor，
照做之後就得到flag。

flag: FLAG{!M_R3V3RS3_E\x11TE}

### GhostShell v2

和V1一樣先把混淆的code清掉之後，用IDA看。
發現它把0xF03020的資料和0x90 xor，之後直接"call 0xF03020"。用x64dbg跟進去看後發現。
![](https://i.imgur.com/YumWUet.png)
它對這群可疑的資料做了可疑的操作。照做之後就發現了flag

flag: FLAG{SH3LLC0D3_I5_N0T_H4RD_T0_R34D}

### GhostShell v3
用x64dbg看它，發現用IDA找到的main的位址，竟然沒辦法在x64dbg看到。
所以只用x64dbg跟了好幾個function，很崩潰。最後放棄跟了。
想到可不可以直接搜memory的資料，
因為V1V2，都會對某些資料做一些操作讓它變成flag，
操作完的東西通常都能在memory找。
後來發現cheat engine能掃memory的東西。用cheat engine直接找"FLAG{"就找到了。
![](https://i.imgur.com/ZaWlOit.png)


flag: FLAG{!M_4_SuP3R_APT_M4LW4RE_H4cKeR}

### Dungeons & Monsters
這就是一個遊戲，打怪獸獲得1分，
打一次會掉一個補包，吃了回1D，
怪獸攻擊會扣1D或2D血。打到100分就有flag。
很明顯扣2D回1D，過不久一定死。
最後發現若你站在補包上面，怪獸在離你1格的地方。
這時候若吃補包，怪獸會跑到你的位置上，但居然不會扣血。
看了原始碼才知道，怪物會先判定攻擊在判定移動。
所以就利用這個洞打到100分。寫一個python code來自動控制。
方法很簡單。
1. 先打一隻怪獸得到一個補包。
2. 再BFS到下一個怪獸的位置，把它引到離補包一格的位置上，吃補包，攻擊它。就這樣遞迴下去到100分。

助教都幫忙把地圖的一些interface給我們了，所以其實還蠻好寫的。
不過我寫得程式有時候會失敗，但多試個1, 2次就能成功了。
![](https://i.imgur.com/NcZL79u.png)

script:
https://github.com/ppappeoh/final_ctf/blob/master/DungeonsAndMonsters.py

flag: flag{You_Pwn3d_the_dunge0n!!!}

### DuoRenSnake
看到server的程式碼
```javascript=
  client.on('admin', (msg, cb) => {
    var ipString = client.handshake.headers['x-forwarded-for'] || client.request.connection.remoteAddress;
    if (ipaddr.IPv4.isValid(ipString)) {

    } else if (ipaddr.IPv6.isValid(ipString)) {
      var ip = ipaddr.IPv6.parse(ipString);
      if (ip.isIPv4MappedAddress()) {
        ipString = ip.toIPv4Address().toString();
      } else {
        // ipString is IPv6
      }
    } else {
      // ipString is invalid
    }

    console.log(ipString);
    if(ipString == "127.0.0.1") {
      cb("FLAG{xxxxxxxxxx}");
    }
  });
```
head裡面x-forward-for是127.0.0.1時就能拿到flag，x-forward-for是能任意填寫的，所以寫了個script，自定了header裡的x-forward-for，送出就能拿到flag。
```javascript
var socket = require('socket.io-client')('http://final.kaibro.tw:10001',{
  extraHeaders: {
    'x-forwarded-for': '127.0.0.1'
  }
});
socket.emit('admin', 'aaa', function(data) {
  console.log(data);
});
```
flag: FLAG{G3t_R3al_IP_1s_50_h4rd}

### Two files
看到
``` php
$file1 = '"' . $file1 . '"';
$file2 = '"' . $file2 . '"';
$cmd = "file $file1 $file2";
system($cmd);
```
就猜這題大概就是cmd injection，
看了file的manpage，沒發現甚麼好用的option，
所以就找有甚麼辦法能run第二種command。最後試出了下面這個payload
```
    f1=\&&f2=%0A l$5s . \
```
f1的\是為了消除file1的右雙引號，這樣子file2的左雙引號就和file1的左雙引號配對。
再來就可以用%0a換行，run第二個command了。
最後記得要把file2的右雙引號消除掉。
ls之間塞一個$5是為了繞過WAF，cat , flag之類的都可以用這種方式繞過。
就像這樣
```
    file "\" "%0a l$5s . \"
```
真的執行了"ls ."，所以基本上get shell了，有辦法拿flag。

![](https://i.imgur.com/h5UHY94.png)

flag:  FLAG{e4sy_w4f_byp4s5_0h_y4_XD__} 

### LOracleVE

m = 明文
c = m^e^ (mod n)
d = 密鑰, dr=密鑰的後516bits，dl=密鑰的剩下bits
題目拿來解密的就是dr，所以我們拿到的是c^dr^。
但我們想要的是c^d^ = c^dr+dl^=c^dr^ * c^dl^。
現在就來猜dl。

∃k∈[0, e) s.t. 

      e*d = k * φ(n) + 1 
      
=> d = (k * φ(n) + 1 )/e

已知e, n，估計φ(n)

φ(n) = (p-1)(q-1) 
= pq - 2(p+q) + 1 
≤ pq - 2$\sqrt{pq}$ + 1
=n - 2*$\sqrt{n}$ + 1

φ(n) 和 n - 2*$\sqrt{n}$ + 1之間的誤差並不大，
我們需要的是d的高位的bits，所以小誤差並不會影響到它的高位的bits。

再來就暴搜e次，就能找到FLAG了。

![](https://i.imgur.com/cOo1cvj.png)

script:
https://github.com/ppappeoh/final_ctf/blob/master/LOracleVE.py

flag: CTF{finaL a1L paSs, WiNNiE oNg}



### babe_tcache

這題的漏洞在delete note時
沒有檢查note是否存在
因此可以重複多次delete note時
直接造成double free

所以跟上課時所敎的fastbin類似

step 1 : malloc一次
step 2 : free兩次, 造成tcache裡的chunk指向自己
step 3 : malloc一次, 並寫入一個「想要的位址」
step 4 : malloc一次, 此時那個「想要的位址」會被移到tcache->entries的第一個

step 5 : 再malloc一次, 這時就可以malloc到「想要的位址」, 
(雖然tcache裡的size欄位會變成負的, 但反正沒有檢查, 所以沒關係)

由此, 我們得到了一個任意位址寫入
下一步就是把free_hook寫成one_gadget寫成system()或one_gadget

但因為本題有開pie且full relro
不能像上課教的用bss段的stdin來leak libc (練習題沒開pie)

所以現在要想辦法leak libc

因為本題最大能malloc的大小就是127
所以沒辦法直接生出fastbin以上的chunk
也就是說
沒辦法直接得到指向main_arena的指標來leak libc

所以現在要想辦法來造出unsortbin

我的想法是
先malloc出一塊chunk
利用前面提到的任意為址寫來修改此chunk的size
再把此chunk給free掉
如此即可造出一個unsortbin
最後再把此chunk給malloc回來 然後印出來
得到libc base後即可去改free_hook
但目前還沒正確實現此想法, 不確定想法是否正確


途中還需先leak出heap base
但這比較簡單
新增note時只輸入'\n'不要把chunk data裡面的tcache pointer指標洗掉
即可得到heap base

另外
tcache跟fastbin的指標指向chunk header跟chunk data的差別
感覺是可以利用的點
但不知道要用在甚麼地方

這題比較困難的地方在於

(1) 只提供兩個指標, 也就是指給我們兩塊chunk操作的空間
(2) 只有new出來的note才能print來leak東西, 相當不方便
(3) 只有在新增note時才能輸入, 相當不方便

PS
這題很多人解出來
助教也在聊天室說是簡單題
但我卻越看越複雜QAQ







 
