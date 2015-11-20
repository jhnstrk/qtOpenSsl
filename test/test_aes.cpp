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


    QTest::newRow("Hello World")       << QByteArray( "Hello World" )      << (int)QAesCrypt::Zeros;
    QTest::newRow("Exactly one block") << QByteArray( "Hello World45678" ) << (int)QAesCrypt::Zeros;
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

    QByteArray initVec = randomBytes( blockSize );

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
