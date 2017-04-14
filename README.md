# ssltimer

### Title
#### SSLTimer: Testing an SSL Implementation with respect to Timing Attack Vulnerability

### Team
Yuchi Tian  

### Introduction
In this project, I will begin with reproducing [Remote Timing Attacks are Practical](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf) in a LAN network setting. Then I will move the server to EC2 and try to explore the statistical ways to identify the timing attack vulnerability by collecting the timing samples from remote servers and analyzing these data.

### Motivation
A timing attack exploits data-dependent behaviorial charactoristics of the implementation of an algorithm. Some implementions of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanlaysis techniques to make the attack more effective. If the implementation of SSL is vulnerable to timing attack, it will cause critical security and privacy issues. There is no existing tools focuing on testing SSL implementations with respect to the timing attack vulnerability. Thus in this project I will try to implement a tool SSLTimer that can collect timing samples from an SSL server and analyze the statistical features of the data to decide if it is vulnerable to timing attack.   
  
### Methodology
CipherSuite: 
   * RSA_WITH_AES_256_CBC_SHA
   * RSA_WITH_AES_128_GCM_SHA256
   * RSA_WITH_AES_256_CCM  
   
SSL:
   * openssl 0.9.7a
   * openssl 0.9.8
   * openssl 1.0.2  

Protocol version:
  * SSLv3 - TLSv1.2
  
Timer:  
* According to RFC 5246, using these cipher suite, as a client initiates a handshake with a TLS server, a 48-byte premaster secret will be encrypted using the public key of the server and sent to server in an ClientKeyExchange message. Then the server will decrypt the premaster secret with its private key. RFC 5246 requires that the 48-byte premaster secret begins with client_version(2 bytes) and followed by 46 random bytes. If the first two bytes are different from the client version, an alert "bad_record_mac" will be sent back from the server and the connection will be terminated by server. By timing the process from the clientKeyExchange message is sent to the alert "bad_record_mac" is received, we can approximate the time that the server uses to decrypt this encrypted premaster secret.  

Intuition:
* We believe that if a server use blinding to protect itself from timing attack, the statistical features of the timing data will be different from the statistical features of the data collected from a server that is vulnerable to timing attack.

Statistical features:

* Timing data distribution with same input
* Timing data variance with different input

### Project plan
1. Implement SSL handshake protocol to automatically collect timing samples from an SSL server.  (Done)
2. Analyze the statistical features of the timing data to decide if it is vulnerable to timing attack. (4/3-4/12)
3. Identify if the analysis process can be automated and complete the remaining part of this tool.  (4/13-4/20)

### Project goal

By collecting and analyzing timing data, I will try to explore a statistical way and automate the process to decide if an SSL server is vulnerable to timing attack on RSA decryption or if an SSL server is immune to this attack by using blinding.  

### Result
Timing data distribution with same input

<img src="https://github.com/yuchi1989/ssltimer/blob/master/result/figure_2(bli).png" width="600">  

         Figure1: timing data distribution for SSL servers using blind  
<img src="https://github.com/yuchi1989/ssltimer/blob/master/result/figure_2(vul).png" width="600">  

         Figure2: timing data distribution for vulnerable SSL servers
<img src="https://github.com/yuchi1989/ssltimer/blob/master/result/figure_6.png" width="600">  

                          Figure3: linearSVC classifier

Data: X: (100,2) Y: (100,)  
10 fold cross validation result: **0.92** (accuracy)  
[ 1.   0.9  0.8  1.   0.8  1.   1.   1.   0.9  0.8]


### Threats to Validity   
Timing attack can happen in RSA signature process or decryption process.  In this project, we only test the cipher suites where RSA is used for key agreement and authentication and test the side channel from the RSA decryption process.  

### Resources
Brumley, D., & Boneh, D. (2005). Remote timing attacks are practical. Computer Networks, 48(5), 701-716.  
Brumley, B. B., & Tuveri, N. (2011, September). Remote timing attacks are still practical. In European Symposium on Research in Computer Security (pp. 355-371). Springer Berlin Heidelberg.  
Morgan, T. D., & Morgan, J. W. (2015). Web Timing Attacks Made Practical.  
Al Fardan, N. J., & Paterson, K. G. (2013, May). Lucky thirteen: Breaking the TLS and DTLS record protocols. In Security and Privacy (SP), 2013 IEEE Symposium on (pp. 526-540). IEEE.  
Chapman, P., & Evans, D. (2011, October). Automated black-box detection of side-channel vulnerabilities in web applications. In Proceedings of the 18th ACM conference on Computer and communications security (pp. 263-274). ACM.  
Scapy-SSL/TLS: https://github.com/tintinweb/scapy-ssl_tls  
RFC 5246: https://tools.ietf.org/html/rfc5246  
RFC 6101: https://tools.ietf.org/html/rfc6101  
mimoo/timing_attack_ecdsa_tls : https://github.com/mimoo/timing_attack_ecdsa_tls  
