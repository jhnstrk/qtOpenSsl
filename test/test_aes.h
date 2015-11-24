#pragma once

#include <QObject>
#include <QTest>

class TestAes: public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();

    void knownAnswerTest_data();
    void knownAnswerTest();

    void testAesEncDec_data();
    void testAesEncDec();

    void testPkcsPadding();
    void testBitPadding();

    void testIncrementalCipher();

};
