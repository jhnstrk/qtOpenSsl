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
        qWarning() << "Bad key length";
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

    default:
        break;
    }
    return out;
}

#include <openssl/rand.h>

QByteArray randomBytes(int len)
{
    QByteArray ret;
    ret.resize( len );
    int status = RAND_bytes(reinterpret_cast<unsigned char*>(ret.data()), len);
    if (status != 1) {
        qWarning() << "Random bytes not available";
    }
    return ret;
}
