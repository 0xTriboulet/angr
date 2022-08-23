Angr's ability to symbolically execute programs is robust and capable of overcoming degrees of randomness that heuristic analysis cannot.

HTB's Impossible Password challenge leverages a rand() system call to randomize the password required to access the flag. The standard
solution is to this challenge is to patch the binary in order to either bypass the randomness or jump to the flag generation function.

But it's possible to defeat this randomness through angr's symbolic execution engines.

![image](https://user-images.githubusercontent.com/22229087/186059055-1d2039c9-897e-4b28-80dc-db1868a37c9a.png)
