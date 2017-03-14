# ssltimer

## Title
#### SSLTimer: Testing if an Implementation of SSL is Vulnerable to Timing Attack

## Team
#### Yuchi Tian

## Motivation
A timing attack exploits data-dependent behaviorial charactoristics of the implementation of an algorithm. Some implementions of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanlaysis techniques to make the attack more effective. If the implementation of SSL is vulnerable to timing attack, it will cause critical security and privacy issues. There is no existing tools focuing on testing the timing attack vulnerability. Thus in this project I will try to design and implement a tool SSLTimer that can analyze and test if an implementation of SSL is vulnerable to timing attack.

## Project plan
1. Configure the SSL server environment and implement the SSL handshake protocol.  
2. Analyze if there is a correlation between key and execution time for some crypto options and specific SSL implementation using statistical methods.  
3. Identify if the anlaysis process can be automated and complete the remaining part of this tool.  

## Related work

## Reference
Brumley, D., & Boneh, D. (2005). Remote timing attacks are practical. Computer Networks, 48(5), 701-716.
