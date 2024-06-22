import crypto from 'crypto';
import { createECDH, createSign, createVerify } from 'crypto';

class SecureCommunication {
  constructor() {
    this.aesKey = null;
    this.ecdh = createECDH('secp256k1');
    this.ecdh.generateKeys();
    this.privateKey = this.ecdh.getPrivateKey();
    this.publicKey = this.ecdh.getPublicKey();
    this.sha3 = crypto.createHash('sha3-512');
  }

  // Simulasi Pertukaran Kunci Kuantum
  async exchangeKeys() {
    // Langkah 1: Alice mengirim qubit ke Bob (disimulasikan)
    const aliceBits = this.generateRandomBits(128);
    const aliceBases = this.generateRandomBits(128);
    
    // Langkah 2: Bob menerima qubit dan memilih basis pengukuran secara acak
    const bobBases = this.generateRandomBits(128);
    const bobBits = this.measureQubits(aliceBits, aliceBases, bobBases);
    
    // Langkah 3: Alice dan Bob mengungkapkan basis pengukuran mereka dan menyimpan bit yang cocok
    const sharedKeyBits = this.compareBases(aliceBases, bobBases, aliceBits, bobBits);
    this.aesKey = crypto.createHash('sha256').update(sharedKeyBits.join('')).digest();
  }

  generateRandomBits(length) {
    return Array.from({ length }, () => Math.round(Math.random()));
  }

  measureQubits(aliceBits, aliceBases, bobBases) {
    return aliceBits.map((bit, index) => (aliceBases[index] === bobBases[index] ? bit : Math.round(Math.random())));
  }

  compareBases(aliceBases, bobBases, aliceBits, bobBits) {
    return aliceBases.map((base, index) => (base === bobBases[index] ? aliceBits[index] : null)).filter(bit => bit !== null);
  }

  encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return { encrypted, iv: iv.toString('hex'), authTag };
  }

  decryptData(encrypted, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.aesKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  hashData(data) {
    this.sha3.update(data);
    return this.sha3.digest('hex');
  }

  signData(hash) {
    const sign = createSign('SHA256');
    sign.update(hash);
    sign.end();
    const signature = sign.sign(this.privateKey, 'hex');
    return signature;
  }

  verifySignature(hash, signature, publicKey) {
    const verify = createVerify('SHA256');
    verify.update(hash);
    verify.end();
    return verify.verify(publicKey, signature, 'hex');
  }

  sendData(data) {
    const { encrypted, iv, authTag } = this.encryptData(data);
    const hash = this.hashData(encrypted);
    const signature = this.signData(hash);
    return { encrypted, iv, authTag, hash, signature, publicKey: this.publicKey.toString('hex') };
  }

  receiveData({ encrypted, iv, authTag, hash, signature, publicKey }) {
    const isVerified = this.verifySignature(hash, signature, publicKey);
    if (!isVerified) {
      throw new Error('Signature verification failed');
    }
    const decrypted = this.decryptData(encrypted, iv, authTag);
    return decrypted;
  }
}

export default SecureCommunication
