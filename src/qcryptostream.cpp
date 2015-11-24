#include "qcryptostream.h"

#include <openssl/bio.h>

#include <QByteArray>
#include <QIODevice>
#include <QDebug>


#include <openssl/aes.h>

class QAesCrypt::Private {
public:
    Private(QAesCrypt::eAesLen len) :
        aesLen(len),
        padding( QAesCrypt::PKCS7 )
    {
    }
    const QAesCrypt::eAesLen aesLen;
    QAesCrypt::ePadding padding;
    QByteArray key;
    QByteArray initVec;

    AES_KEY enc_key;
    AES_KEY dec_key;
    unsigned char iv[AES_BLOCK_SIZE];
};

QAesCrypt::QAesCrypt(eAesLen len)
: d( new QAesCrypt::Private(len))
{
    ::memset(d->iv, 0, sizeof(d->iv));
    ::memset(&d->enc_key, 0, sizeof(AES_KEY));
    ::memset(&d->dec_key, 0, sizeof(AES_KEY));
}

QAesCrypt::~QAesCrypt()
{
    delete d;
    d = NULL;
}


void QAesCrypt::setPadding( ePadding padding )
{
    d->padding = padding;
}

QAesCrypt::ePadding QAesCrypt::padding() const
{
    return d->padding;
}

int QAesCrypt::expectedKeyLen() const
{
    return d->aesLen;
}

void QAesCrypt::initialize( const QByteArray & key, const QByteArray & initVec)
{
    d->key = key;
    d->initVec = initVec;

    if (key.size() != this->expectedKeyLen()) {
        qWarning() << "Bad key length, expected" << this->expectedKeyLen();
        d->key.resize( this->expectedKeyLen() );
    }

    if (initVec.size() != AesBlockSize) {
        qWarning() << "Bad initialization vector length";
        d->initVec.resize( AesBlockSize );
    }

    int status = -1;
    status = AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(d->key.constData()),
            d->aesLen * 8, &d->enc_key);
    if (status != 0){
        qWarning() << "Status"<< status;
    }

    status = AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(d->key.constData()),
            d->aesLen * 8, &d->dec_key);
    if (status != 0){
        qWarning() << "Status"<< status;
    }

    ::memcpy(d->iv, d->initVec.constData(), AES_BLOCK_SIZE);
}

QByteArray QAesCrypt::aesEnc (const QByteArray & input)
{
    int numFullBlocks = ( input.size() )/ AES_BLOCK_SIZE;
    int numBlocks;
    int fullLen;
    switch( d->padding ){
    case QAesCrypt::PKCS7:
    case QAesCrypt::BitPadding:
        numBlocks = ( input.size() + AES_BLOCK_SIZE )/ AES_BLOCK_SIZE;
        fullLen = numFullBlocks * AES_BLOCK_SIZE;
        break;
    case QAesCrypt::NoPadding:
    case QAesCrypt::Zeros:
        numFullBlocks = ( input.size() + (AES_BLOCK_SIZE -1) )/ AES_BLOCK_SIZE;
        numBlocks = numFullBlocks;
        fullLen = input.size();
        break;
    default:
        numBlocks = ( input.size() + (AES_BLOCK_SIZE -1) )/ AES_BLOCK_SIZE;
        fullLen = numFullBlocks * AES_BLOCK_SIZE;
        break;
    }

    const int encsLen = numBlocks * AES_BLOCK_SIZE;
    QByteArray out;
    out.resize(encsLen);

    AES_cbc_encrypt(
            reinterpret_cast<const unsigned char *>(input.constData()),
            reinterpret_cast<unsigned char *>(out.data()),
            fullLen,
            &d->enc_key,
            d->iv,
            AES_ENCRYPT);

    switch( d->padding ){
    case QAesCrypt::PKCS7:
    {
        const int auxLen = encsLen - fullLen;
        QByteArray padding(auxLen, '\0');
        // Copy input
        for (int i=0; i<input.size() - fullLen; ++i){
            padding[i] = input.at(fullLen + i);
        }
        // Add padding
        const int nPadding = encsLen - input.size();
        for (int i=input.size() - fullLen; i<auxLen;++i) {
            padding[i] = nPadding;
        }
        AES_cbc_encrypt(
                reinterpret_cast<const unsigned char *>(padding.constData()),
                reinterpret_cast<unsigned char *>(out.data()) + fullLen,
                auxLen,
                &d->enc_key,
                d->iv,
                AES_ENCRYPT);
    }
        break;
    case QAesCrypt::BitPadding:
    {
        const int auxLen = encsLen - fullLen;
        QByteArray padding(auxLen, '\0');
        // Copy input
        for (int i=0; i<input.size() - fullLen; ++i){
            padding[i] = input.at(fullLen + i);
        }
        // Add padding (zeros were already added from initialization).
        const int nPadding = encsLen - input.size();
        padding[input.size() - fullLen] = 1;

        AES_cbc_encrypt(
                reinterpret_cast<const unsigned char *>(padding.constData()),
                reinterpret_cast<unsigned char *>(out.data()) + fullLen,
                auxLen,
                &d->enc_key,
                d->iv,
                AES_ENCRYPT);
    }
        break;
    case QAesCrypt::NoPadding:
    case QAesCrypt::Zeros:
        break;
    default:
        break;
    }

    return out;
}


QByteArray QAesCrypt::aesDec ( const QByteArray & input)
{
    QByteArray out;
    out.resize(input.size());

    AES_cbc_encrypt(
            reinterpret_cast<const unsigned char *>(input.constData()),
            reinterpret_cast<unsigned char *>(out.data()),
            input.size(),
            &d->dec_key,
            d->iv,
            AES_DECRYPT);

    switch( d->padding) {
    case QAesCrypt::Zeros:
        {
            int i = out.size() -1;
            for ( ; i >= 0; --i) {
                if (out.at(i) != 0) {
                    ++i;
                    break;
                }
            }
            if (i >= 0) {
                out.resize(i);
            } else {
                out.resize(0);
            }
        }
        break;
    case QAesCrypt::PKCS7:
    {
        if (out.isEmpty()){
            return out; // Strictly not in spec.
        }
        int nPad = out.at(out.size() - 1);
        out.chop( nPad );
    }
    break;
    case BitPadding:
    {
        int iEnd = out.size();
        while (iEnd > 0){
            --iEnd;
            int padVal = out.at(iEnd);
            if (padVal == 0) {
                continue;
            } else if (padVal == 1) {
                break;
            } else {
                qWarning() << "Unexpected padding" << padVal;
                break;
            }
        }
        out.resize(iEnd);
        return out;
    }
    break;
    default:
        break;
    }
    return out;
}

#include <openssl/rand.h>

QByteArray qRandomBytes(int len, bool * ok)
{
    QByteArray ret(len, '\0');

    int status = RAND_bytes(reinterpret_cast<unsigned char*>(ret.data()), len);
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }

    if (ok) {
        *ok = (status == 0);
    }
    return ret;
}
