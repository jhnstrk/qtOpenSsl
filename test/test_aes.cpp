#include "test_aes.h"

#include <qcryptostream.h>

#include <QByteArray>
#include <QDebug>

QTEST_MAIN(TestAes)

namespace {
    static const QByteArray Same = "Same";
}
void TestAes::initTestCase()
{

}

void TestAes::cleanupTestCase()
{

}

void TestAes::knownAnswerTest_data()
{
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("iv");
    QTest::addColumn<QByteArray>("plain");
    QTest::addColumn<QByteArray>("cipher");

    const QByteArray zeroIv = QByteArray::fromHex("00000000000000000000000000000000");
    const QByteArray zeroPlain = QByteArray::fromHex("00000000000000000000000000000000");

    // AES256 test vectors from NIST.
    QTest::newRow("0")  << QByteArray::fromHex("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558")
        <<  zeroIv << zeroPlain
        <<  QByteArray::fromHex("46f2fb342d6f0ab477476fc501242c5f");

    QTest::newRow("63")  << QByteArray::fromHex("ffffffffffffffff000000000000000000000000000000000000000000000000")
            <<  zeroIv << zeroPlain
            <<  QByteArray::fromHex("94efe7a0e2e031e2536da01df799c927");


}
void TestAes::knownAnswerTest()
{
    QFETCH( QByteArray, key);
    QFETCH( QByteArray, iv);
    QFETCH( QByteArray, plain);
    QFETCH( QByteArray, cipher);

    qDebug() << "INP:" << plain.toHex();

    QAesCrypt encoder( QAesCrypt::Aes256 );
    encoder.setPadding( QAesCrypt::Zeros);
    encoder.initialize(key, iv);

    QByteArray enc = encoder.aesEnc(plain);
    qDebug() << "ENC:" << enc.toHex();

    QCOMPARE(enc, cipher);

    QAesCrypt decoder( QAesCrypt::Aes256 );
    decoder.setPadding( QAesCrypt::NoPadding);
    decoder.initialize(key, iv);

    QByteArray dec = decoder.aesDec(cipher);
    qDebug() << "DEC:" << dec.toHex();

    QCOMPARE( dec, plain);

}

void TestAes::testAesEncDec_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<int>("padding");

    QTest::newRow("Short")       << QByteArray( "H" )      << (int)QAesCrypt::Zeros;
    QTest::newRow("Short")       << QByteArray( "H" )      << (int)QAesCrypt::PKCS7;
    QTest::newRow("Empty")       << QByteArray( "" )      << (int)QAesCrypt::Zeros;
    QTest::newRow("Empty")       << QByteArray( "" )      << (int)QAesCrypt::PKCS7;

    QTest::newRow("Hello World")       << QByteArray( "Hello World" )      << (int)QAesCrypt::Zeros;
    QTest::newRow("Exactly one block") << QByteArray( "Hello World45678" ) << (int)QAesCrypt::Zeros;
    QTest::newRow("Hello World - PKCS7")       << QByteArray( "Hello World" )      << (int)QAesCrypt::PKCS7;
    QTest::newRow("Exactly one block PKCS7") << QByteArray( "Hello World45678" ) << (int)QAesCrypt::PKCS7;


}

void TestAes::testAesEncDec()
{
    QByteArray key;
    int aesLen = 256;
    int len = aesLen / 8;
    int blockSize = QAesCrypt::AesBlockSize;
    key = "MyKey";
    key.resize(len);


    QFETCH( int, padding);
    QFETCH( QByteArray, input);
    QAesCrypt::ePadding paddingE = (QAesCrypt::ePadding)padding;

    QByteArray initVec = qRandomBytes( blockSize );

    qDebug() << "INP:" << input.toHex();

    QAesCrypt encoder( QAesCrypt::Aes256 );
    encoder.initialize(key, initVec);
    encoder.setPadding(paddingE);

    QByteArray enc = encoder.aesEnc(input);
    qDebug() << "ENC:" << enc.toHex();

    QAesCrypt decoder( QAesCrypt::Aes256 );
    decoder.initialize(key, initVec);
    decoder.setPadding(paddingE);

    QByteArray dec = decoder.aesDec(enc);
    qDebug() << "DEC:" << dec.toHex();

    QCOMPARE( dec, input);

}

void TestAes::testPkcsPadding()
{
    QAesCrypt encoderRaw( QAesCrypt::Aes256 );
    const QByteArray key="asdfqwerghjktyuiasdfqwerghjktyui";
    const QByteArray initVec(QAesCrypt::AesBlockSize, 0);
    encoderRaw.initialize(key, initVec);
    encoderRaw.setPadding(QAesCrypt::NoPadding);

    QAesCrypt encoderPadded( QAesCrypt::Aes256 );
    encoderPadded.initialize(key, initVec);
    encoderPadded.setPadding(QAesCrypt::PKCS7);

    for ( int i =0; i<QAesCrypt::AesBlockSize-1; ++i) {
        QByteArray unPadded(QAesCrypt::AesBlockSize + i, '\0' );

        QByteArray padded( 2*QAesCrypt::AesBlockSize, '\0' );

        for (int j=i; j< QAesCrypt::AesBlockSize; ++j){
            padded[QAesCrypt::AesBlockSize+j] = QAesCrypt::AesBlockSize - i;
        }
        // qDebug() << "PAD:" << padded.toHex();
        // qDebug() << "UNP:" << unPadded.toHex();

        QByteArray encExp = encoderRaw.aesEnc(padded);
        QByteArray encAct = encoderPadded.aesEnc(unPadded);
        QCOMPARE( encAct, encExp );
    }

}
void TestAes::testBitPadding()
{
    QAesCrypt encoderRaw( QAesCrypt::Aes256 );
    const QByteArray key="asdfqwerghjktyuiasdfqwerghjktyui";
    const QByteArray initVec(QAesCrypt::AesBlockSize, 0);
    encoderRaw.initialize(key, initVec);
    encoderRaw.setPadding(QAesCrypt::NoPadding);

    QAesCrypt encoderPadded( QAesCrypt::Aes256 );
    encoderPadded.initialize(key, initVec);
    encoderPadded.setPadding(QAesCrypt::BitPadding);

    for ( int i =0; i<QAesCrypt::AesBlockSize-1; ++i) {
        QByteArray unPadded( QAesCrypt::AesBlockSize + i, 'a' );

        QByteArray padded( 2*QAesCrypt::AesBlockSize, 'a' );

        for (int j= i + 1; j< QAesCrypt::AesBlockSize; ++j){
            padded[QAesCrypt::AesBlockSize+j] = 0;
        }
        padded[QAesCrypt::AesBlockSize+i] = 1;

        qDebug() << "PAD:" << padded.toHex();
        qDebug() << "UNP:" << unPadded.toHex();

        QByteArray encExp = encoderRaw.aesEnc(padded);
        QByteArray encAct = encoderPadded.aesEnc(unPadded);
        QCOMPARE( encAct, encExp );
    }

}

void TestAes::testIncrementalCipher()
{
    // Compare encoding by blocks, against encoding one big block.
    // Result should be the same.
    QAesCrypt encoderBlocks( QAesCrypt::Aes256 );
    const QByteArray key="asdfqwerghjktyuiasdfqwerghjktyui";
    const QByteArray initVec(QAesCrypt::AesBlockSize, 0);
    encoderBlocks.initialize(key, initVec);
    encoderBlocks.setPadding(QAesCrypt::NoPadding);

    QByteArray bigBlockPlain;
    QByteArray blockEnc;
    for (int i=0; i< 5; ++i) {
        QByteArray oneBlock( QAesCrypt::AesBlockSize, (char) ( i % 0x100 ) );
        blockEnc.append( encoderBlocks.aesEnc(oneBlock) );
        bigBlockPlain.append( oneBlock );
    }

    QAesCrypt encoderBigBlock( QAesCrypt::Aes256 );
    encoderBigBlock.initialize(key, initVec);
    encoderBigBlock.setPadding(QAesCrypt::NoPadding);
    QByteArray bigBlockCipher = encoderBigBlock.aesEnc( bigBlockPlain );

    QCOMPARE ( blockEnc, bigBlockCipher);

    // And decoding:
    QByteArray blockDec;
    encoderBlocks.initialize(key, initVec);

    for (int i=0, numBlock = bigBlockCipher.size() / QAesCrypt::AesBlockSize; i< numBlock; ++i) {
        QByteArray oneBlock( bigBlockCipher.mid(i*QAesCrypt::AesBlockSize, QAesCrypt::AesBlockSize));
        blockDec.append( encoderBlocks.aesDec( oneBlock) );
    }

    QCOMPARE ( blockDec, bigBlockPlain);


}
