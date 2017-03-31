# ssltimer

### Title
#### SSLTimer: Testing an SSL Implementation with respect to Timing Attack Vulnerability

### Team
Yuchi Tian  

### Introduction
In this project, I will begin with reproducing [Remote Timing Attacks are Practical](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf) in a LAN network setting. Then I will move the server to EC2 and try to explore the statistical ways to identify the timing attack vulnerability by collecting the timing samples from remote servers and analyzing these data.

### Motivation
A timing attack exploits data-dependent behaviorial charactoristics of the implementation of an algorithm. Some implementions of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanlaysis techniques to make the attack more effective. If the implementation of SSL is vulnerable to timing attack, it will cause critical security and privacy issues. There is no existing tools focuing on testing SSL implementations with respect to the timing attack vulnerability. Thus in this project I will try to design and implement a tool SSLTimer that can analyze and test if an implementation of SSL is vulnerable to timing attack on RSA decryption.   
  

### Project plan
1. Implement SSL handshake protocol to automatically collect timing samples from a SSL server.  
2. Analyze if an implementation of SSL is vulnerable to the timing attack on RSA decryption.
3. Identify if the analysis process can be automated and complete the remaining part of this tool.  

### Resources
Brumley, D., & Boneh, D. (2005). Remote timing attacks are practical. Computer Networks, 48(5), 701-716.  
Brumley, B. B., & Tuveri, N. (2011, September). Remote timing attacks are still practical. In European Symposium on Research in Computer Security (pp. 355-371). Springer Berlin Heidelberg.  
Morgan, T. D., & Morgan, J. W. (2015). Web Timing Attacks Made Practical.  
Al Fardan, N. J., & Paterson, K. G. (2013, May). Lucky thirteen: Breaking the TLS and DTLS record protocols. In Security and Privacy (SP), 2013 IEEE Symposium on (pp. 526-540). IEEE.  
Chapman, P., & Evans, D. (2011, October). Automated black-box detection of side-channel vulnerabilities in web applications. In Proceedings of the 18th ACM conference on Computer and communications security (pp. 263-274). ACM.  
Scapy-SSL/TLS: https://github.com/tintinweb/scapy-ssl_tls  
RFC 5246: https://tools.ietf.org/html/rfc5246  
mimoo/timing_attack_ecdsa_tls : https://github.com/mimoo/timing_attack_ecdsa_tls  
