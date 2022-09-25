**The Challenge**

In this script, we use Angr to attack the Headache challenge on HTB.

This binary has a pretty robust anti-debugging instruction set, so tools like Ghidra and BinaryNinja are not super useful.

In fact, running a naive angr script against this binary gets us a false flag!

![image](https://user-images.githubusercontent.com/22229087/192160117-1b0093b0-36b7-42b2-8189-ad10fcd349e2.png)

**The Actual Solution**

After some analysis with gdb and r2, we discover that angr is failing the ptrace checks that are baked into the program. We can overcome this in a couple of different ways, the easiest, is to simply tell angr to avoid the false flag!

![image](https://user-images.githubusercontent.com/22229087/192160176-967b09e1-c6dd-4e72-99e4-7ba1c4aaf638.png)


**The Takeaway**

Angr's ability to avoid addresses and strings is a very powerful capbility.

