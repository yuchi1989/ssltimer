# ssltimer

### Title

#### SSLTimer: Testing an SSL Implementation with respect to Timing Attack Vulnerability
### [slides](https://docs.google.com/a/virginia.edu/presentation/d/134ILvlbyl5amdfGbwuomMzfeKx-8t_G-0JNtCQrmRKQ/edit?usp=sharing)

### Team
Yuchi Tian  


### Introduction
In this project, I will design and implement SSLTimer, a tool that can identify if an SSL secured web server is vulnerable to a specific timing attack by only interacting with the web server remotely. Specifically, I will use the RSA timing vulnerability discussed in [Remote Timing Attacks are Practical](https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf). 

### Motivation
A timing attack exploits data-dependent behaviorial charactoristics of the implementation of an algorithm. Some implementions of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanlaysis techniques to make the attack more effective. If the implementation of SSL is vulnerable to timing attack, it will cause critical security and privacy issues. There is no existing tools focuing on testing SSL implementations with respect to the timing attack vulnerability. Thus in this project, I will propose a statistic based black-box test methodology to identify if an SSL secured web server is vulnerable to a specific timing attack. I will also design and implement a tool SSLTimer to automate the whole testing process.

### Project plan
1. Implement SSL handshake protocol to automatically collect timing samples from an SSL server.  (Done)
2. Analyze the statistical features of the timing data to decide if it is vulnerable to timing attack. (4/3-4/12)
3. Identify if the analysis process can be automated and complete the remaining part of this tool.  (4/13-4/20)

### Project goal

By collecting and analyzing timing data, I will try to explore a statistical way and automate the process to decide if an SSL server is vulnerable to timing attack on RSA decryption or if an SSL server is immune to this attack by using blinding. 

### Methodology

#### Time the RSA decryption of all the possible combination of the top two bits twice, record peak features and compute the variance.

#### Peak Feature
<img src="https://github.com/yuchi1989/ssltimer/blob/master/result/figure_22.png" width="500"> 
For example, the figure above is the result of timing the RSA decryption of all the possible combination of the top two bits.  
Then the recorded peak feature is  [1, 0, 1, 0]. 1 means peak while 0 means not peak.  
If an SSL server is vulnerable, the peak features of the two timing should be similar.   
For example, we get same peak feature for two timing, shown as follows. Then we will get 0 mean variance.    
First round:  
Peak feature [1, 0, 1, 0]  
Second round:  
Peak feature [1, 0, 1, 0]  
Var = [0, 0, 0, 0]  
Mean Variance = 0  

The mean variance range from 0 to 0.25. The mean variances in the following example is 0.25.  
First round [0, 1, 0, 1]  
Second round[1, 0, 1, 0]  
Variance [0.25, 0.25, 0.25, 0.25]  
Mean Variance 0.25  

### Implementation
* According to RFC 5246, using these cipher suite, as a client initiates a handshake with a TLS server, a 48-byte premaster secret will be encrypted using the public key of the server and sent to server in an ClientKeyExchange message. Then the server will decrypt the premaster secret with its private key. RFC 5246 requires that the 48-byte premaster secret begins with client_version(2 bytes) and followed by 46 random bytes. If the first two bytes are different from the client version, an alert "bad_record_mac" will be sent back from the server and the connection will be terminated by server. By timing the process from the clientKeyExchange message is sent to the alert "bad_record_mac" is received, we can approximate the time that the server uses to decrypt this encrypted premaster secret.  


 

### Evaluation
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
SSLTimer cannot guarantee whether the tested servers are vulnerable or not.
Even SSLTimer gets 0 variance as result, it still cannot guarantee the vulnerability because the blinding techniques may intentionally trick it.
When SSLTimer gets very large variance, it means that the server is not vulnerable to this attack at this moment and this environment. (Testing the same servers in different time and environments are necessary).

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
