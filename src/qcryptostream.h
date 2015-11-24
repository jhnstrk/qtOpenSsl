#ifndef QCRYPTOSTREAM_H__
#define QCRYPTOSTREAM_H__

class QByteArray;

class QAesCrypt {
public:
    enum eAesLen { Aes128 = 16, Aes192 = 24, Aes256 = 32 };
    enum ePadding {
        NoPadding,   // Encoder will pad with zeros, decoder will leave full blocks
        Zeros,      // Encoder pads with zeros to fill current block. Decoder strips trailing zeros.
        PKCS7,      // Fills with number of bytes of padding used. Adds a block if input is exact multiple of block.
        BitPadding  // Fills with 1,0,0,....0
    };

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

QByteArray qRandomBytes(int len, bool * ok = 0);

#endif // QCRYPTOSTREAM_H__
