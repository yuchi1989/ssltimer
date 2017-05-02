# ssltimer

### Title

#### SSLTimer: Testing an SSL Implementation with respect to Timing Attack Vulnerability
### [slides](https://docs.google.com/a/virginia.edu/presentation/d/134ILvlbyl5amdfGbwuomMzfeKx-8t_G-0JNtCQrmRKQ/edit?usp=sharing)

### Team
Yuchi Tian  


### Introduction
In this project, I will design and implement SSLTimer, a tool that can identify if an SSL secured web server is vulnerable to a specific timing attack by only interacting with the web server remotely. Specifically, I will use the RSA timing vulnerability discussed in [Remote Timing Attacks are Practical](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf). 

### Motivation
A timing attack exploits data-dependent behavioral characteristics of the implementation of an algorithm. Some implementations of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanalysis techniques to make the attack more effective. If the implementation of SSL is vulnerable to timing attack, it will cause critical security and privacy issues. There is no existing tools focusing on black-box testing SSL implementations with respect to the timing attack vulnerability. Thus in this project, I will propose a statistic based black-box test methodology to identify if an SSL secured web server is vulnerable to a specific timing attack. I will also design and implement a tool SSLTimer to automate the whole testing process.

### Methodology

#### Time the RSA decryption of all the possible combination of the top two bits twice, record peak features and compute the variance.

#### Peak Feature
<img src="https://github.com/yuchi1989/ssltimer/blob/master/result/figure_22.png" width="500"> 

The figure above is an example result of timing the RSA decryption of all the possible combination of the top two bits.  
The peak feature of the result is  [1, 0, 1, 0]. 1 means peak while 0 means not peak.  We will do the timing twice, get two peak features and compute the variance.
  
For example, if we get same peak feature for two consecutive timing as follows. Then we will get 0 mean variance.   
First round:  
Peak feature [1, 0, 1, 0]  
Second round:  
Peak feature [1, 0, 1, 0]  
Variance = [0, 0, 0, 0]  
Mean Variance = 0  

The mean variance ranges from 0 to 0.25. The following example shows the maximum mean variance.  
First round:  
Peak feature [0, 1, 0, 1]  
Second round:  
Peak feature [1, 0, 1, 0]  
Variance [0.25, 0.25, 0.25, 0.25]  
Mean Variance 0.25  

If the SSL server is vulnerable, the two peak features for two consecutive timing should be similar. I will use mean variance to decide if the SSL server is vulnerable or not. If the mean variance is 0 or close to 0, then the SSL server is vulnerable. If the mean variance is not close to 0, then the SSL server is not vulnerable.  

### Implementation

According to RFC 5246, using RSA for key agreement, as a client initiates a handshake with a TLS server, a 48-byte premaster secret will be encrypted using the public key of the server and sent to server in a ClientKeyExchange message. Then the server will decrypt the premaster secret with its private key. RFC 5246 requires that the 48-byte premaster secret begins with client_version(2 bytes) and followed by 46 random bytes. 

We can use any input as the premaster secret in a ClientKeyExchange message and send it to the TLS server. The server will decrypt it using the private key. But if the input does not meet the format of a 48-byte premaster secret, the TLS server will send an alert "bad_record_mac" and terminate the connection. 

I will use our guessed q as the premaster secret and timing the process from sending the ClientKeyExchange message to receiving the TLS alert.

I use [Python-scapy-tls_ssl](https://github.com/tintinweb/scapy-ssl_tls) to implement the TLS handshake and timing process.  Since I will use RSA for key agreement, the cipher suites will be RSA_WITH_AES_256_CBC_SHA, RSA_WITH_AES_128_GCM_SHA256 or RSA_WITH_AES_256_CCM. 

### Evaluation

#### Experiment setting
* OS: Ubuntu 16.04 VM
* SSL implementation: openssl-0.9.7 and openssl-1.0.2
* SSL-version: TLS 1.0
* Key size: 1024

#### Experiment method
Run SSLTimer 20 times for the web server using openssl-0.9.7 and compute the average of the mean variance.
Run SSLTimer 20 times for the web server using openssl-1.0.2 and compute the average of the mean variance.

#### Result

openssl-0.9.7: Average of mean variance: 0.109

openssl-1.0.2: Average of mean variance: 0.125

#### Discussion
The result is not as good as I expect. The mean variance for openssl-1.0.2 is reasonable, but the mean variance for openssl-0.9.7 should be much smaller or 0. This probably results from the imprecise timing. Therefore, in future, we may try to implement SSLTimer in C and use CPU cycles to measure the time.

### Threats to Validity   
SSLTimer cannot guarantee whether the tested servers are vulnerable or not.
Even the mean variance of peak features is 0, we still cannot guarantee the vulnerability because the blinding techniques may intentionally trick it.
When the mean variance of peak features is not close to 0, it means that the server is not vulnerable to this attack at this moment and this environment. We should also test the same server at different time and environments.

### Future work
* Implement SSLTimer using C socket and measure the time using CPU cycles.
* Let the tested server be hosted in different Amazon EC2 servers, located in different cities or countries.

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
