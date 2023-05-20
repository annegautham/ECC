package ecc; // put in folder called ecc so it has access to every other .java file in it

import java.math.BigInteger;
import java.util.Random;
import java.io.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * This class implements El Gamal Public-Key Cryptography using Elliptic Curve! It is very cool!
 * It also implements key-pair generations!
 */
public class ECC {
    public static final long AUXILIARY_CONSTANT_LONG = 1000;
    public static final BigInteger AUXILIARY_CONSTANT = BigInteger.valueOf(AUXILIARY_CONSTANT_LONG);
    
    // tracks time of the last action, in millisecond, as per Ms. Pandya's idea!
    private static long executionTime = -1;
    private static long startExecutionTime;
    
    /**
     * This was the main encryption algorithm which takes bytes of plain nexts and a key of PublicKey object type.
     */
    public static byte[] encrypt(byte[] plainText, PublicKey key) throws Exception {
        initializeExecutionTime();
        EllipticCurve c = key.getCurve();
        ECPoint g = c.getBasePoint();
        ECPoint publicKey = key.getKey();
        BigInteger p = c.getP();
        int numBits = p.bitLength();
        int blockSize = getBlockSize(c);
        int cipherTextBlockSize = getCipherTextBlockSize(c);
        // initializes the cipher block size according to data from plain text
        
        // this pads the goofy plainText
        byte[] padded = pad(plainText, blockSize);
        
        // Chunk the plainText into blocks.
        byte[][] block = new byte[padded.length / blockSize][blockSize];
        for (int i = 0; i < block.length; ++i) { // oWINIONOIN THIS DON'T WORK!!!!!! WHYYYY
            for (int j = 0; j < blockSize; ++j) {
                block[i][j] = padded[i * blockSize + j];
            }
        }
        
        // Encode each block into unique point on the elliptic curve!
        ECPoint[] encoded = new ECPoint[block.length];
        for (int i = 0; i < encoded.length; ++i) {
            encoded[i] = encode(block[i], c);
        }
        
        // Encrypt each encoded point into a pair of points:
        // [x, y] = [kB, m + g], where:
        // k is a randomly generated integer such that 1 <= k < p-1,
        // G is the base point (provided in the key),
        // m is the encoded point from the plain text,
        // g is the point provided in the public key.
        // yayyYYY!


        ECPoint[][] encrypted = new ECPoint[block.length][2];
        Random rnd = new Random(System.currentTimeMillis());
        for (int i = 0; i < encrypted.length; ++i) {
            BigInteger k;
            do {
                k = new BigInteger(numBits, rnd);
            } while (k.mod(p).compareTo(BigInteger.ZERO) == 0);
            encrypted[i][0] = c.multiply(g, k);
            encrypted[i][1] = c.add(encoded[i], c.multiply(publicKey, k));
        } // encoding text to cipher by appending to 2D array of text/cipher
        
        // transforms the ciphertext as an array of bytes

        byte[] cipherText = new byte[encrypted.length * cipherTextBlockSize * 4];
        for (int i = 0; i < encrypted.length; ++i) {

            // encrypted[0].x, I think - need to check
            byte[] cipher = encrypted[i][0].x.toByteArray();
            int offset = i * cipherTextBlockSize * 4 + cipherTextBlockSize * 0 + (cipherTextBlockSize - cipher.length);
            for (int j = 0; j < cipher.length; ++j) {
                cipherText[j + offset] = cipher[j];
            }
            // encrypted[0].y, I think - need to check
            cipher = encrypted[i][0].y.toByteArray();
            offset = i * cipherTextBlockSize * 4 + cipherTextBlockSize * 1 + (cipherTextBlockSize - cipher.length);
            for (int j = 0; j < cipher.length; ++j) {
                cipherText[j + offset] = cipher[j];
            }
            // encrypted[1].x, I think - need to check
            cipher = encrypted[i][1].x.toByteArray();
            offset = i * cipherTextBlockSize * 4 + cipherTextBlockSize * 2 + (cipherTextBlockSize - cipher.length);
            for (int j = 0; j < cipher.length; ++j) {
                cipherText[j + offset] = cipher[j];
            }
            // encrypted[1].y, I think - need to check
            cipher = encrypted[i][1].y.toByteArray();
            offset = i * cipherTextBlockSize * 4 + cipherTextBlockSize * 3 + (cipherTextBlockSize - cipher.length);
            for (int j = 0; j < cipher.length; ++j) {
                cipherText[j + offset] = cipher[j];
            }
        }
        
        finalizeExecutionTime();
        
        return cipherText;
    }
    
    /**
     * The main decryption function of ECC.
     */
    public static byte[] decrypt(byte[] cipherText, PrivateKey key) throws Exception {
        initializeExecutionTime();
        
        EllipticCurve c = key.getCurve();
        ECPoint g = c.getBasePoint();
        BigInteger privateKey = key.getKey();
        BigInteger p = c.getP();
        int numBits = p.bitLength();
        int blockSize = getBlockSize(c);
        int cipherTextBlockSize = getCipherTextBlockSize(c);
        
        // split cipherText into blocks.
        if (cipherText.length % cipherTextBlockSize != 0 || (cipherText.length / cipherTextBlockSize) % 4 != 0) {
            throw new Exception("The length of the cipher text is not valid");
        }
        byte block[][] = new byte[cipherText.length / cipherTextBlockSize][cipherTextBlockSize];
        for (int i = 0; i < block.length; ++i) {
            for (int j = 0; j < cipherTextBlockSize; ++j) {
                block[i][j] = cipherText[i * cipherTextBlockSize + j];
            }
        } // plzzzzz workkkkkk
        
        // Calculate the encoded point
        // m = y - kx, where:
        // [x, y] is the ciphertext,
        // k is the private key.

        ECPoint encoded[] = new ECPoint[block.length / 4];
        for (int i = 0; i < block.length; i += 4) {
            ECPoint c1 = new ECPoint(new BigInteger(block[i]), new BigInteger(block[i + 1]));
            ECPoint c2 = new ECPoint(new BigInteger(block[i + 2]), new BigInteger(block[i + 3]));
            encoded[i / 4] = c.subtract(c2, c.multiply(c1, privateKey));
        }
        
        // decoding function
        byte plainText[] = new byte[encoded.length * blockSize];
        for (int i = 0; i < encoded.length; ++i) {
            byte decoded[] = decode(encoded[i], c);
            for (int j = Math.max(blockSize - decoded.length, 0); j < blockSize; ++j) {
                plainText[i * blockSize + j] = decoded[j + decoded.length - blockSize];
            }
        }
        plainText = unpad(plainText, blockSize);
        
        finalizeExecutionTime();
        return plainText;
    }
    
    /**
     * Generate a random key-pair, given the elliptic curve being used.
     */
    public static KeyPair generateKeyPair(EllipticCurve c, Random rnd) throws Exception {
        initializeExecutionTime();
        
        // Randomly select the coprime private key to p

        BigInteger p = c.getP();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(p.bitLength(), rnd);
        } while (privateKey.mod(p).compareTo(BigInteger.ZERO) == 0);
        
        // Calculate the public key, k * g.
        // First, randomly generate g if it is not present in the curve - i think this is how it works?!!!

        ECPoint g = c.getBasePoint();
        if (g == null) {
            // Koblits method.
            // random x starting value
            BigInteger x = new BigInteger(p.bitLength(), rnd);
            g = koblitzProbabilistic(c, x);
            c.setBasePoint(g);
        }
        ECPoint publicKey = c.multiply(g, privateKey);
        
        KeyPair result = new KeyPair(
                new PublicKey(c, publicKey),
                new PrivateKey(c, privateKey)
        );
        
        finalizeExecutionTime();
        return result;
    }
    
    /**
     * return execution time!!!!
     */
    public static long getLastExecutionTime() {
        return executionTime;
    }
    
    /**
     * Return the encoded point from a block of byte.
     */
    private static ECPoint encode(byte[] block, EllipticCurve c) throws Exception {
        // pad two zero byte
        byte[] paddedBlock = new byte[block.length + 2];
        for (int i = 0; i < block.length; ++i) {
            paddedBlock[i + 2] = block[i];
        }
        return koblitzProbabilistic(c, new BigInteger(paddedBlock));
    }
    
    /**
     * Return the encoded block from a point.
     */
    private static byte[] decode(ECPoint point, EllipticCurve c) {
        return point.x.divide(AUXILIARY_CONSTANT).toByteArray();
    }
    
    /**
     * block size of plain text in bytes.
     * 
     * This assumes that the order of g over p is very close to |c|, as the
     * recommended cofactor must be no larger than 4.
     * 
     * The chosen block size is max((bitLength(p) / 8) - 5, 1).
     */
    private static int getBlockSize(EllipticCurve c) {
        return Math.max(c.getP().bitLength() / 8 - 5, 1);
    }
    
    private static int getCipherTextBlockSize(EllipticCurve c) {
        return c.getP().bitLength() / 8 + 5;
    }
    
    /**
     * Pad the array of byte b so its length will be multiple of blockSize.
     * 
     * There will be at least one byte padded. The last byte will contain the
     * number of padded bytes.
     */
    private static byte[] pad(byte[] b, int blockSize) {
        int paddedLength = blockSize - (b.length % blockSize);
        byte[] padded = new byte[b.length + paddedLength];
        for (int i = 0; i < b.length; ++i) {
            padded[i] = b[i];
        }
        for (int i = 0; i < paddedLength - 1; ++i) {
            padded[b.length + i] = 0;
        }
        padded[padded.length - 1] = (byte)paddedLength;
        
        return padded;
    }
    
    /**
     * Recover the original array of byte given the padded array of byte b.
     * NEED TO TEST $red$
     */
    private static byte[] unpad(byte[] b, int blockSize) {
        int paddedLength = b[b.length - 1];
        byte[] unpadded = new byte[b.length - paddedLength];
        for (int i = 0; i < unpadded.length; ++i) {
            unpadded[i] = b[i];
        }
        return unpadded;
    }
    
    /**
     * Find a point inside the curve with the x-coordinate equals
     * x * AUXILIARY_CONSTANT + k, where k is small as possible.
     * 
     * This method works only for p = 3 (mod 4), as finding the solution to
     * the quadratic congruence is can't work for p = 1 (mod 4). If
     * p equals 1 (mod 4), an exception will also be thrown. it's basically a bunc of mathy math I found from this paper!
     * http://www.ams.org/journals/mcom/1987-48-177/S0025-5718-1987-0866109-5/S0025-5718-1987-0866109-5.pdf
     *
     */
    private static ECPoint koblitzProbabilistic(EllipticCurve c, BigInteger x) throws Exception {
        BigInteger p = c.getP();
        
        // throw an exception if p != 3 (mod 4)
        if (!p.testBit(0) || !p.testBit(1)) {
            throw new Exception("P should be 3 (mod 4)");
        }
        BigInteger pMinusOnePerTwo = p.subtract(BigInteger.ONE).shiftRight(1);
        
        BigInteger tempX = x.multiply(AUXILIARY_CONSTANT).mod(p);
        for (long k = 0; k < AUXILIARY_CONSTANT_LONG; ++k) {
            BigInteger newX = tempX.add(BigInteger.valueOf(k));
            
            // Calculates the rhs of the elliptic curve equation, call it a
            BigInteger a = c.calculateRhs(newX);
            
            // Determine whether this value is a quadratic residue modulo p
            // It is if and only if a ^ ((p - 1) / 2) = 1 (mod p)
            if (a.modPow(pMinusOnePerTwo, p).compareTo(BigInteger.ONE) == 0) {
                // YYYAYYY, we found it! Now, the solution is y = a ^ ((p + 1) / 4)
                BigInteger y = a.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
                return new ECPoint(newX.mod(p), y);
            }
        }
        
        // If reaches, then no point are found within the limit.
        throw new Exception("No point found within the auxiliary constant");
    }
    
    private static void initializeExecutionTime() {
        startExecutionTime = System.currentTimeMillis();
    }
    
    private static void finalizeExecutionTime() {
        executionTime = System.currentTimeMillis() - startExecutionTime;
    }
    
    public static void main(String[] args) throws Exception {
        // using NIST_P_192 to test

        EllipticCurve c = EllipticCurve.NIST_P_192;
        Random rnd = new Random(System.currentTimeMillis());
        
        int nTest = 10;
        int failed = 0;
        int size = 242; // can change size
        
        //File path = new File("/Users/anneg/Desktop/123007Q4LinuxProject/123007Q4LinuxProject/src/ecc/moo.txt");

        byte[] test = new byte[size];
        //byte[] test = method(path);
        for (int itest = 0; itest < nTest; ++itest) {
            System.out.println("Test " + itest + ": " + size + " Bytes");
            // randomize test
            rnd.nextBytes(test);
            
            // makes pair of keys
            KeyPair keys = generateKeyPair(c, rnd);
            System.out.println("\tGenerating key pair: " + getLastExecutionTime() + " ms");
            
            // encrypt test
            byte[] cipherText = encrypt(test, keys.getPublicKey());
            System.out.println("\tEncrypting         : " + getLastExecutionTime() + " ms");
            
            // decrypt the result
            byte[] plainText = decrypt(cipherText, keys.getPrivateKey());
            System.out.println("\tDecrypting         : " + getLastExecutionTime() + " ms");
            
            // compare them
            boolean match = test.length == plainText.length;
            for (int i = 0; i < test.length && i < plainText.length && match; ++i) {
                if (test[i] != plainText[i]) {
                    match = false;
                    failed++;
                }
            }
            System.out.println("\tResult             : " + match);
            
//         
//                ECPoint point = encode(test, c);
//                byte[] decoded = decode(point, c);
//                boolean correctlyDecoded = true;
//                for (int j = 0; j < test.length || j < decoded.length; ++j) {
//                    if (j < test.length && j < decoded.length) {
//                        if (test[test.length - j - 1] != decoded[decoded.length - j - 1]) {
//                            correctlyDecoded = false;
//                            break;
//                        }
//                    }
//                    else if (j < test.length) {
//                        if (test[test.length - j - 1] != 0) {
//                            correctlyDecoded = false;
//                            break;
//                        }
//                    }
//                }
//                
//                System.out.println("testing " + i + " (encode) = " + c.isPointInsideCurve(point) + " " + point.toString());
//                System.out.println("testing " + i + " (decode) = " + correctlyDecoded);
//                
//                if (!correctlyDecoded) {
//                    failed++;
//                }
//            } catch (Exception ex) {
////                System.out.println("testing " + i + " failed: " + ex.getMessage());
//                ex.printStackTrace();
//                failed++;
//            }
        }
        
        System.out.println("Failed: " + failed + " of " + nTest); //counts number of times point on ECC was not able to be found!
    }


    public static byte[] method(File file) //
        throws IOException
    {
        // Creating an object of FileInputStream to
        // read from a file
        FileInputStream fl = new FileInputStream(file);
  
        // Now creating byte array of same length as file
        byte[] arr = new byte[(int)file.length()];
  
        // Reading file content to byte array
        // using standard read() method
        fl.read(arr);
  
        // lastly closing an instance of file input stream
        // to avoid memory leakage
        fl.close();
  
        // Returning above byte array
        return arr;
    }
}
