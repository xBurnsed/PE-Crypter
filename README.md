# PoC-Packer
This is my end degree project.

This project aims to implement a crypter (also known as Software Packer) as a Proof of Concept and to detail which obfuscation techniques can be used to convert a currently detected malware executable into an undetectable executable both in scan time and run time towards commercial antivirus. 
The crypter consists of three main blocks: encryption of the malware, creation of a stub with the ability to decrypt itself and self-loading of the decrypted malware directly into memory without touching the hard drive. 

To be able to implement the stub it is necessary to choose between several code injection methods. In this case, the Process Hollowing method has been chosen.
In short, Process Hollowing is a technique based on: a) creating a new process in a suspended state, b) modifying the content with the image of another executable (in this case, for the already decrypted bytes containing the malware), c) making the necessary modifications for the correct execution of the new process, d) resuming the execution of this new process which now contains the malware bytes in its memory space. 
In this project, additional obfuscation techniques to the crypter will be used and documented to improve the results obtained from it. Some of these techniques are the following: obfuscation of imports, digital certificate cloning or anti-emulation, among others.
In order to evaluate the effectiveness of the crypter created, tests will be carried out using a website that acts as an antivirus multiscanner. This website offers the possibility of scanning any executable file with the 26 most renowned commercial antiviruses, obtaining the results almost instantly. The purpose of this work is to reduce the detection rates of any malware to the lowest possible, the best result being a FUD (Fully Undetectable) malware file, by using the crypter with additional obfuscation techniques.
