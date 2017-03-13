# ssltimer

## Title
#### SSLTimer: Testing if an Implementation of SSL is Vulnerable to Timing Attack

## Team
#### Yuchi Tian

## Motivation
A timing attack exploits data-dependent behaviorial charactoristics of the implementation of an algorithm. Some implementions of cryptographic algorithms including RSA are vulnerable to timing attack. In these implementations, there may exist a correlation between key and the encryption time and the time information can be exploited to infer keys. The information leaked by measuring time can also be combined with other cryptanlaysis techniques to make the attack more effective. Some implementations of SSL are probably vulnerable to timing attack, too. It can cause critical security and privacy issues. However, there is no existing tools focuing on testing the timing attack vulnerability. Thus I propose to design and implement a tool SSLTimer that can test if an implementation of SSL is vulnerable to timing attack.

## Project plan

## Related work
