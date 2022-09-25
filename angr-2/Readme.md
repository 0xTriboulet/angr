**The Challenge**

Angr's ability to symbolically execute programs is robust and capable of overcoming degrees of randomness that heuristic analysis cannot.

HTB's Impossible Password challenge leverages a rand() system call to randomize the password required to access the flag. 

**The First Solution**

The standard solution is to this challenge is to patch the binary in order to either bypass the randomness or jump to the flag generation function.

But it's possible to defeat this randomness through angr's symbolic execution engines.


![image](https://user-images.githubusercontent.com/22229087/186059483-120ff67f-6ec3-4e2d-9ed5-182d96f84ecf.png)

**The Second Solution**

Using angr's auto_load_libs=False and force_load_libs options, we can can import a custom rand() function, and generate deterministic
"impossible passwords" during symbolic execution. The output clarity is improved for this script as demonstrated below.

![image](https://user-images.githubusercontent.com/22229087/186065822-47ed6745-6901-4e4d-9d94-4e73ac6ea7a2.png)

