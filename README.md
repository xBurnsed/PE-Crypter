# C++ Crypter
This is my Final Degree Project.

This project aims to implement a crypter (also known as Software Packer) as a Proof of Concept and to detail which obfuscation techniques can be used to convert a currently detected malware executable into an undetectable executable both in scan time and run time towards commercial antivirus. 

The crypter consists of three main blocks: encryption of the malware, creation of a stub with the ability to decrypt itself and self-loading of the decrypted malware directly into memory without touching the hard drive. 

To be able to implement the stub it is necessary to choose between several code injection methods. In this case, the Process Hollowing method has been chosen.
In short, Process Hollowing is a technique based on: a) creating a new process in a suspended state, b) modifying the content with the image of another executable (in this case, for the already decrypted bytes containing the malware), c) making the necessary modifications for the correct execution of the new process, d) resuming the execution of this new process which now contains the malware bytes in its memory space. 

In this project, additional obfuscation techniques to the crypter will be used and documented to improve the results obtained from it. Some of these techniques are the following: obfuscation of imports, digital certificate cloning or anti-emulation, among others.

In order to evaluate the effectiveness of the crypter created, tests will be carried out using a website that acts as an antivirus multiscanner. This website offers the possibility of scanning any executable file with the 26 most renowned commercial antiviruses, obtaining the results almost instantly. The purpose of this work is to reduce the detection rates of any malware to the lowest possible, the best result being a FUD (Fully Undetectable) malware file, by using the crypter with additional obfuscation techniques.


The implementation of this project is divided in four subprojects:

 - PEEncrypter: This corresponds to the Builder of the crypter. This project is responsible of encrypting an executable (".exe") received as an input using RC4 algorithm, encoding this encrypted bytes with Base64 (to reduce entropy) and outputting the resulting bytes in a header (".h") file.
 - PELoader: This corresponds to the Stub of the crypter. This part is in charge of decoding and decrypting the bytes read from the header (".h") file and applying the Process Hollowing method previously described.
 - SignatureClone: This project is an additional obfuscation method used to improve the results. It consists of clonning the digital signature from a well known executable (like Spotify.exe) into any executable.
 - WebApp: This consists of a simple webapp (Flask and ReactJS) to representate the project visually and automatize the procedure of using the Crypter.

![image](https://user-images.githubusercontent.com/14180748/126828226-21dd706d-4ea1-4e83-85b6-6c44d97ad863.png)

Those were the results I got from a well known malware called Remcos (reduced from 23/26 detections to 0/26 detections):

![remcosCrypt](https://user-images.githubusercontent.com/14180748/126828407-bb906b31-f650-4eb7-a260-74c0d715893b.png)

For the runtime I manually tested some Antivirus like Panda, Avira, Windows Defender... etc. None of those were able to detect the malware after going through my Crypter.




