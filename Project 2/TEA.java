import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class TEA {
    
    // Define constants for the TEA algorithm
    private static final int DELTA = 0x9e3779b9;
    private static final int ROUNDS = 32;
    
    // Encrypt a single 64-bit block using the TEA algorithm
    public static byte[] encryptBlock(byte[] plainBlock, int[] key) {
        // Split the block into two 32-bit halves
        int v0 = ByteBuffer.wrap(plainBlock, 0, 4).getInt();
        int v1 = ByteBuffer.wrap(plainBlock, 4, 4).getInt();
        int sum = 0;
        // Apply the TEA encryption algorithm for a fixed number of rounds
        for (int i = 0; i < ROUNDS; i++) {
            sum += DELTA;
            v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
            v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        }
        // Combine the two halves back into a single block
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.putInt(v0);
        buf.putInt(v1);
        return buf.array();
    }
    
    // XOR two arrays of bytes together
    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
    
    // Pad a plaintext message to a multiple of 8 bytes
    public static byte[] padPlaintext(byte[] plainText) {
        int remainder = plainText.length % 8;
        int paddingNeeded = remainder == 0 ? 0 : 8 - remainder;
        byte[] padded = new byte[plainText.length + paddingNeeded];
        System.arraycopy(plainText, 0, padded, 0, plainText.length);
        return padded;
    }
    
    // Encrypt a message using CBC mode with TEA encryption
    public static byte[] encryptCBC(byte[] plainText, int[] key, byte[] iv) {
        // Pad the plaintext message to a multiple of 8 bytes
        byte[] paddedPlainText = padPlaintext(plainText);
        byte[] encrypted = new byte[paddedPlainText.length];
        byte[] prevBlock = iv;
        // Encrypt each block of the message using CBC mode
        for (int i = 0; i < paddedPlainText.length; i += 8) {
            // XOR the plaintext block with the previous ciphertext block
            byte[] plainBlock = xorBytes(paddedPlainText, prevBlock);
            // Encrypt the XORed block using TEA
            byte[] encryptedBlock = encryptBlock(plainBlock, key);
            // Copy the encrypted block to the output buffer
            System.arraycopy(encryptedBlock, 0, encrypted, i, 8);
            // Remember the current ciphertext block for the next iteration
            prevBlock = encryptedBlock;
        }
        return encrypted;
    }
    
    public static void main(String[] args) {
        // Define the plaintext to be encrypted
        byte[] plainText = new byte[] {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        
        // Define the key to be used for encryption and decryption
        int[] key = new int[] {0xa56bacd0, 0x00000000, 0xffffffff, 0xabcdef01};
    
        // Generate random IV (Initialization Vector) to be used in CBC (Cipher Block Chaining) mode
        byte[] iv = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
    
        // Encrypt the plaintext using the key and IV
        byte[] encrypted = encryptCBC(plainText, key, iv);
        System.out.println("Encrypted: " + bytesToHex(encrypted));
        
        // Decrypt the ciphertext using the key and IV
        byte[] decrypted = decryptCBC(encrypted, key, iv);
        System.out.println("Decrypted: " + bytesToHex(decrypted));
    }
    
    // Helper function to convert a byte array to a hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static byte[] decryptBlock(byte[] cipherBlock, int[] key) {
        // Extract two integers from the cipher block using the ByteBuffer class
        int v0 = ByteBuffer.wrap(cipherBlock, 0, 4).getInt();
        int v1 = ByteBuffer.wrap(cipherBlock, 4, 4).getInt();
        
        // Initialize the sum variable to DELTA * ROUNDS
        int sum = DELTA * ROUNDS;
        
        // Perform a series of operations on v0 and v1 in ROUNDS iterations
        for (int i = 0; i < ROUNDS; i++) {
            v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
            v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
            sum -= DELTA;
        }
        
        // Convert v0 and v1 back into a byte array and return it
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.putInt(v0);
        buf.putInt(v1);
        return buf.array();
    }
    
    public static byte[] decryptCBC(byte[] encrypted, int[] key, byte[] iv) {
        // Create a new byte array to store the decrypted message
        byte[] decrypted = new byte[encrypted.length];
        
        // Initialize prevBlock to the initialization vector (iv)
        byte[] prevBlock = iv;
        
        // Decrypt each 8-byte block in the encrypted message and store it in the decrypted array
        for (int i = 0; i < encrypted.length; i += 8) {
            // Extract the current block from the encrypted message
            byte[] encryptedBlock = Arrays.copyOfRange(encrypted, i, i + 8);
            
            // Decrypt the current block using the decryptBlock method
            byte[] decryptedBlock = decryptBlock(encryptedBlock, key);
            
            // XOR the decrypted block with the previous block (or iv for the first block)
            byte[] plainBlock = xorBytes(decryptedBlock, prevBlock);
            
            // Store the plaintext block in the decrypted array
            System.arraycopy(plainBlock, 0, decrypted, i, 8);
            
            // Update prevBlock to be the current encrypted block for the next iteration
            prevBlock = encryptedBlock;
        }
        
        // Return the decrypted message
        return decrypted;
    }
}
