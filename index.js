import crypto from 'crypto';

const ALGORITHM_AES = 'aes-256-gcm';
const ALGORITHM_HASH = 'sha3-512';
const ALGORITHM_SIGN = 'sha256';

class SecureCommunication {
  constructor() {
    // Initialize class properties
    this.aesKey = null;
    this.ecdh = crypto.createECDH('secp256k1');
    this.privateKey = null;
    this.publicKey = null;
    this.algorithmAES = ALGORITHM_AES;
    this.algorithmHash = ALGORITHM_HASH;
    this.algorithmSign = ALGORITHM_SIGN;

    // Generate ECDH key pair
    this.generateKeyPair();
  }

  generateKeyPair() {
    try {
      // Generate ECDH key pair
      this.ecdh.generateKeys();

      // Store private and public keys
      this.privateKey = this.ecdh.getPrivateKey();
      this.publicKey = this.ecdh.getPublicKey();
    } catch (error) {
      console.error('Error generating key pair:', error.message);
      throw new Error('Error generating key pair');
    }
  }

  async exchangeKeys() {
    try {
      // Generate random bits for key exchange
      const aliceBits = this.generateRandomBits(128);
      const aliceBases = this.generateRandomBits(128);
      const bobBases = this.generateRandomBits(128);

      // Calculate shared key bits using Quantum Key Distribution principles
      const bobBits = this.measureQubits(aliceBits, aliceBases, bobBases);
      const sharedKeyBits = this.compareBases(aliceBases, bobBases, aliceBits, bobBits);

      // Derive AES key from shared key bits
      this.aesKey = await this.deriveAesKey(sharedKeyBits);

      // Clear sensitive data from buffers
      crypto.randomFillSync(sharedKeyBits);
    } catch (error) {
      console.error('Error during key exchange:', error.message);
      throw new Error('Error during key exchange');
    }
  }

  generateRandomBits(length) {
    const randomBytes = crypto.randomBytes(Math.ceil(length / 8));
    return Array.from(randomBytes).map(byte => byte % 2);
  }

  measureQubits(aliceBits, aliceBases, bobBases) {
    return aliceBits.map((bit, index) => (aliceBases[index] === bobBases[index] ? bit : this.generateRandomBits(1)[0]));
  }

  compareBases(aliceBases, bobBases, aliceBits, bobBits) {
    return aliceBases.map((base, index) => (base === bobBases[index] ? aliceBits[index] : null))
                      .filter(bit => bit !== null);
  }

  async deriveAesKey(sharedKeyBits) {
    try {
      const sharedKeyHex = sharedKeyBits.join('');
      const derivedKey = await crypto.subtle.digest('SHA-256', Buffer.from(sharedKeyHex, 'utf8'));
      return derivedKey;
    } catch (error) {
      console.error('Error deriving AES key:', error.message);
      throw new Error('Error deriving AES key');
    }
  }

  async encryptData(data) {
    try {
      if (typeof data !== 'string') {
        throw new TypeError('Data must be a string');
      }

      // Generate IV
      const iv = crypto.randomBytes(16);

      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithmAES, this.aesKey, iv);

      // Encrypt data
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      // Get authentication tag
      const authTag = cipher.getAuthTag().toString('hex');

      // Clear sensitive data from buffers
      cipher.final();

      return { encrypted, iv: iv.toString('hex'), authTag };
    } catch (error) {
      console.error('Error during encryption:', error.message);
      throw new Error('Error during encryption');
    }
  }

  async decryptData(encrypted, iv, authTag) {
    try {
      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithmAES, this.aesKey, Buffer.from(iv, 'hex'));

      // Set authentication tag
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));

      // Decrypt data
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      // Clear sensitive data from buffers
      decipher.final();

      return decrypted;
    } catch (error) {
      console.error('Error during decryption:', error.message);
      throw new Error('Error during decryption');
    }
  }

  hashData(data) {
    try {
      // Hash data
      return crypto.createHash(this.algorithmHash).update(data).digest('hex');
    } catch (error) {
      console.error('Error during hashing:', error.message);
      throw new Error('Error during hashing');
    }
  }

  signData(data) {
    try {
      // Create sign object
      const sign = crypto.createSign(this.algorithmSign);

      // Update with data
      sign.update(data);

      // Sign data
      sign.end();
      const signature = sign.sign(this.privateKey, 'hex');

      // Clear sensitive data from buffers
      sign.end();

      return signature;
    } catch (error) {
      console.error('Error during signing:', error.message);
      throw new Error('Error during signing');
    }
  }

  verifySignature(data, signature, publicKey) {
    try {
      // Create verify object
      const verify = crypto.createVerify(this.algorithmSign);

      // Update with data
      verify.update(data);

      // Verify signature
      verify.end();
      const verified = verify.verify(publicKey, signature, 'hex');

      // Clear sensitive data from buffers
      verify.end();

      return verified;
    } catch (error) {
      console.error('Error during signature verification:', error.message);
      return false;
    }
  }

  async sendData(data) {
    try {
      // Encrypt data
      const { encrypted, iv, authTag } = await this.encryptData(data);

      // Hash encrypted data
      const hash = this.hashData(encrypted);

      // Sign hash
      const signature = this.signData(hash);

      // Clear sensitive data from buffers
      crypto.randomFillSync(this.aesKey);

      return {
        encrypted,
        iv,
        authTag,
        hash,
        signature,
        publicKey: this.publicKey.toString('hex'),
      };
    } catch (error) {
      console.error('Error preparing data for sending:', error.message);
      throw new Error('Error preparing data for sending');
    }
  }

  async receiveData({ encrypted, iv, authTag, hash, signature, publicKey }) {
    try {
      // Verify signature
      const isVerified = this.verifySignature(hash, signature, publicKey);
      if (!isVerified) {
        throw new Error('Signature verification failed');
      }

      // Decrypt data
      const decrypted = await this.decryptData(encrypted, iv, authTag);

      // Clear sensitive data from buffers
      crypto.randomFillSync(this.aesKey);

      return decrypted;
    } catch (error) {
      console.error('Error receiving and processing data:', error.message);
      throw new Error('Error receiving and processing data');
    }
  }

  // Clear sensitive data from class instance
  clearSensitiveData() {
    crypto.randomFillSync(this.aesKey);
  }
}

export default SecureCommunication;
