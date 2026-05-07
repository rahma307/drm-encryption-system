// crypto-device.js - Cryptographic Device Identity
class CryptoDeviceManager {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
        this.keyId = null;
    }

    // توليد RSA key pair جديد
    async generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true, // قابل للتصدير عشان نحفظه
            ["sign", "verify"]
        );

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;
        
        // استخراج المفتاح العام عشان نرسله للسيرفر
        const publicKeySpki = await crypto.subtle.exportKey("spki", this.publicKey);
        this.keyId = await this.computeKeyId(publicKeySpki);
        
        return { privateKey: this.privateKey, publicKey: this.publicKey, keyId: this.keyId };
    }

    async computeKeyId(publicKeySpki) {
        const hash = await crypto.subtle.digest("SHA-256", publicKeySpki);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("")
            .slice(0, 32);
    }

    // حفظ المفاتيح في IndexedDB (أكثر أماناً من localStorage)
    async saveKeys() {
        const exportedPriv = await crypto.subtle.exportKey("pkcs8", this.privateKey);
        const exportedPub = await crypto.subtle.exportKey("spki", this.publicKey);
        
        const keyData = {
            privateKey: Array.from(new Uint8Array(exportedPriv)),
            publicKey: Array.from(new Uint8Array(exportedPub)),
            keyId: this.keyId
        };
        
        localStorage.setItem("crypto_device_keys", JSON.stringify(keyData));
        localStorage.setItem("crypto_device_id", this.keyId);
    }

    // تحميل المفاتيح من التخزين
    async loadKeys() {
        const saved = localStorage.getItem("crypto_device_keys");
        if (!saved) return null;
        
        const keyData = JSON.parse(saved);
        
        const privateKeyRaw = new Uint8Array(keyData.privateKey);
        const publicKeyRaw = new Uint8Array(keyData.publicKey);
        
        this.privateKey = await crypto.subtle.importKey(
            "pkcs8", privateKeyRaw,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false, ["sign"]
        );
        
        this.publicKey = await crypto.subtle.importKey(
            "spki", publicKeyRaw,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false, ["verify"]
        );
        
        this.keyId = keyData.keyId;
        return this;
    }

    // توقيع payload
    async signPayload(payload) {
        if (!this.privateKey) await this.loadKeys();
        if (!this.privateKey) throw new Error("No device key initialized");
        
        const encoder = new TextEncoder();
        const data = encoder.encode(payload);
        
        const signature = await crypto.subtle.sign(
            "RSASSA-PKCS1-v1_5",
            this.privateKey,
            data
        );
        
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

    // إنشاء أو تحميل هوية الجهاز
    async init() {
        const existing = await this.loadKeys();
        if (existing) {
            return existing;
        }
        
        await this.generateKeyPair();
        await this.saveKeys();
        return this;
    }

    // الحصول على device ID للتخزين (التوافق مع الكود القديم)
    getDeviceId() {
        return this.keyId;
    }
}

// Singleton instance
window.cryptoDevice = new CryptoDeviceManager();