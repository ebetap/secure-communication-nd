import crypto from 'crypto';

const ALGORITHM_AES = 'aes-256-gcm';
const ALGORITHM_HASH = 'sha3-512';
const ALGORITHM_SIGN = 'sha256';

class SecureCommunication {
  #aesKey = null;
  #ecdh = crypto.createECDH('secp256k1');
  #privateKey = null;
  #publicKey = null;
  #algorithmAES = ALGORITHM_AES;
  #algorithmHash = ALGORITHM_HASH;
  #algorithmSign = ALGORITHM_SIGN;

  constructor() {
    this.generateKeyPair();
  }

  generateKeyPair() {
    try {
      this.#privateKey = this.#ecdh.generateKeys('hex', 'compressed');
      this.#publicKey = this.#ecdh.getPublicKey('hex', 'compressed');
    } catch (error) {
      console.error('Error generating key pair:', error.message);
      throw new Error('Error generating key pair');
    }
  }

  async exchangeKeys() {
    try {
      const aliceBits = this.generateRandomBits(128);
      const aliceBases = this.generateRandomBits(128);
      const bobBases = this.generateRandomBits(128);

      const bobBits = this.measureQubits(aliceBits, aliceBases, bobBases);
      const sharedKeyBits = this.compareBases(aliceBases, bobBases, aliceBits, bobBits);

      this.#aesKey = await this.deriveAesKey(sharedKeyBits);

      // Clear sensitive data
      this.clearSensitiveData();

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

      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(this.#algorithmAES, this.#aesKey, iv);

      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag().toString('hex');

      cipher.final();

      return { encrypted, iv: iv.toString('hex'), authTag };
    } catch (error) {
      console.error('Error during encryption:', error.message);
      throw new Error('Error during encryption');
    }
  }

  async decryptData(encrypted, iv, authTag) {
    try {
      const decipher = crypto.createDecipheriv(this.#algorithmAES, this.#aesKey, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      decipher.final();

      return decrypted;
    } catch (error) {
      console.error('Error during decryption:', error.message);
      throw new Error('Error during decryption');
    }
  }

  hashData(data) {
    try {
      return crypto.createHash(this.#algorithmHash).update(data).digest('hex');
    } catch (error) {
      console.error('Error during hashing:', error.message);
      throw new Error('Error during hashing');
    }
  }

  signData(data) {
    try {
      const sign = crypto.createSign(this.#algorithmSign);
      sign.update(data);
      sign.end();
      const signature = sign.sign(this.#privateKey, 'hex');
      sign.end();

      return signature;
    } catch (error) {
      console.error('Error during signing:', error.message);
      throw new Error('Error during signing');
    }
  }

  verifySignature(data, signature, publicKey) {
    try {
      const verify = crypto.createVerify(this.#algorithmSign);
      verify.update(data);
      verify.end();
      const verified = verify.verify(publicKey, signature, 'hex');
      verify.end();

      return verified;
    } catch (error) {
      console.error('Error during signature verification:', error.message);
      return false;
    }
  }

  async sendData(data) {
    try {
      const { encrypted, iv, authTag } = await this.encryptData(data);
      const hash = this.hashData(encrypted);
      const signature = this.signData(hash);

      this.clearSensitiveData();

      return {
        encrypted,
        iv,
        authTag,
        hash,
        signature,
        publicKey: this.#publicKey,
      };
    } catch (error) {
      console.error('Error preparing data for sending:', error.message);
      throw new Error('Error preparing data for sending');
    }
  }

  async receiveData({ encrypted, iv, authTag, hash, signature, publicKey }) {
    try {
      const isVerified = this.verifySignature(hash, signature, publicKey);
      if (!isVerified) {
        throw new Error('Signature verification failed');
      }

      const decrypted = await this.decryptData(encrypted, iv, authTag);

      this.clearSensitiveData();

      return decrypted;
    } catch (error) {
      console.error('Error receiving and processing data:', error.message);
      throw new Error('Error receiving and processing data');
    }
  }

  clearSensitiveData() {
    crypto.randomFillSync(this.#aesKey);
    this.#privateKey = null;
    this.#ecdh = null;
  }
}

export default SecureCommunication;
