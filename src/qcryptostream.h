#ifndef QCRYPTOSTREAM_H__
#define QCRYPTOSTREAM_H__

class QByteArray;

class QAesCrypt {
public:
    enum eAesLen { Aes128 = 16, Aes192 = 24, Aes256 = 32 };
    enum ePadding { NoPadding, Zeros, ANSI_X923, PKCS7, ISO_IEC_7816_4 };

    QAesCrypt(eAesLen len = Aes128);
    ~QAesCrypt();

    void setPadding( ePadding value);
    ePadding padding() const;

    void initialize( const QByteArray & key, const QByteArray & initVec );
    void uninitialize();

    QByteArray aesEnc (const QByteArray & input);
    QByteArray aesDec (const QByteArray & input);

    static const int AesBlockSize = 16;

    int expectedKeyLen() const;
private:
    class Private;
    Private * d;
};

QByteArray randomBytes(int len);

#endif // QCRYPTOSTREAM_H__
