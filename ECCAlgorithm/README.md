## Getting Started

I developed a Java implementation of ECC (Elliptic Curve Cryptography)! I think it is pretty cool! There are two parts to it - One being the ECC time modification and the other being the mainframe(work) of ECC!

## Sources

I'd like to credit these sources for helping me develop the ECC implementation as well as for modifying your code.
https://medium.com/asecuritysite-when-bob-met-alice/elgamal-and-elliptic-curve-cryptography-ecc-8b72c3c3555e
https://www.geeksforgeeks.org/java-program-to-convert-file-to-a-byte-array/
https://crypto.stackexchange.com/questions/9987/elgamal-with-elliptic-curves
https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/
https://www.researchgate.net/publication/272162532_Implementation_of_ElGamal_Elliptic_Curve_Cryptography_over_prime_field_using_C
https://ieeexplore.ieee.org/document/7033751
https://techdocs.broadcom.com/us/en/ca-mainframe-software/performance-and-storage/ca-netmaster-shared-content-library/12-2/reportcenter/implementing-z-os-mainframe-java.html
https://netbeans.apache.org/tutorials/nbm-propertyeditors-integration.html
https://www.youtube.com/watch?v=dCvB-mhkT0w
https://www.youtube.com/watch?v=gAtBM06xwaw
https://www.youtube.com/watch?v=lRY8ZDek8R0&list=PLSM8fkP9ppPrC3WbrMdED5_X7lxUoIx5Y

## How to Use It
So, the main file is ECC.java, which contains the main method. There are several java files that develop the framework for the ECC decryption and encryption, such as EllipticCurve.java, which contains several Elliptic Curves from the NIST dataset! For the main file, if you go to the main method, you can change the size of the random byte generator, and the output results in generating a key pair, encrypting the bytes, and decrypting them. Please do not exceed the byte size of 2^16 (max is 2^31-1, but that is if you have enough memory), my computer just straight up crashed when I ran this. Unfortunately, I tried using geeks for geeks for information on reading bytes from txt file, but I wasn't able to complete the run, because I ran out of time, so I settled for random bytes. If possible, change your path in File path = _____ to be your txt file - I included a sample moo.txt you could use.

For the mainframe, run mainframe.java. You should see that the java file compiles and opens up a UI, which you can interact with. Unless you know some possible parameters off of the top of your head, try picking one of the NIST datasets and geneate public and private keys, which you should save (both of them!) You can then encrypt by picking various parameters (try 3 and 7 for example) and browsing for your (txt) file - I included moo.txt for your convenience! Base point could be literally anything, because of the kolibitz method! After you enter decrypt, you should see the original message in content, along with its decryption - hopefully it works! Don't pick parameter values of 1 mod 4 because the Nist Curves do not plot them since quadriatics are not solved in this parameter space.

Have fun with it!!! It was too painful for me for you not to have fun with it!