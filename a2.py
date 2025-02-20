import numpy as np

class A2:

    #Computes the public key vector b.
    def generate_public_key_vector(self, A, s, e, p):
        A = np.array(A)
        s = np.array(s)
        e = np.array(e)
        
        b = (np.dot(A, s) + e) % p
        return b
    
    #Encrypts a message using the LWE algorithm.
    def encrypt(self, public_key, random_vector, message, p):
        A, b = public_key
        A = np.array(A)
        b = np.array(b)
        
        # Select rows based on the random binary vector
        A_sum = np.sum(A[random_vector], axis=0) % p
        b_sum = np.sum(b[random_vector]) % p
        
        # Add floor(p/2) if message is 1
        if message == 1:
            b_sum = (b_sum + (p // 2)) % p
        
        return (A_sum, b_sum)
    
    #Decrypts a message using the LWE algorithm.
    def decrypt(self, private_key, ciphertext, p):
        A_sum, b_sum = ciphertext
        s = np.array(private_key)
        
        computed_value = np.dot(A_sum, s) % p
        decrypted_value = (b_sum - computed_value) % p
        
        return 1 if abs(decrypted_value - (p // 2)) < abs(decrypted_value - 0) else 0
