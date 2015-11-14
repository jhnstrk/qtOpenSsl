#include <openssl/bio.h>

#include <QByteArray>
#include <QIODevice>

class qtBio {
public:
    qtBio(BIO * pBio);

protected:
    int read( char * p, int len )
    {
        return (int) m_io->read( p, (qint64) len);
    }

    int write( const char * p, int len )
    {
        return (int) m_io->write( p, (qint64) len);
    }

    //! Write null terminated string
    int write( const char * p )
    {
        return (int) m_io->write( p );
    }

    int readToNul( char * p, int maxlen)
    {
        for (int count = 0; count < maxlen; ++count){
            char c;
            bool ok = m_io->getChar( &c );
            if (!ok) {
                return count;
            }
            *p++ = c;
            if (c == '\0'){
                return count;
            }
        }
        return maxlen;
    }
private:
    static int bwrite(BIO *, const char *, int);
    static int bread(BIO *, char *, int);
    static int bputs(BIO *, const char *);
    static int bgets(BIO *, char *, int);
    static long ctrl(BIO *, int, long, void *);
    static int create(BIO *);
    static int destroy(BIO *);
    static long callback_ctrl(BIO *, int, bio_info_cb *);
    static long callback(struct bio_st * bio,int mode,const char * argp,int argi, long argl,long ret);

    QByteArray m_name;

    BIO_METHOD * m_method;
    BIO * m_bio;
    QIODevice * m_io;
};




qtBio::qtBio(BIO * pBio) :
        m_bio(pBio)
{
    ::memset(m_method, 0, sizeof(BIO_METHOD));

    m_method->bwrite = qtBio::bwrite;
    m_method->bread = qtBio::bread;
    m_method->bputs = qtBio::bputs;
    m_method->bgets = qtBio::bgets;
    m_method->ctrl = qtBio::ctrl;
    m_method->create = qtBio::create;
    m_method->destroy = qtBio::destroy;
    m_method->callback_ctrl = qtBio::callback_ctrl;
    m_method->name = m_name.constData();

    m_bio->method = m_method;
    m_bio->callback = qtBio::callback;
    m_bio->ptr = this;
}


int qtBio::bwrite(BIO * bio, const char * p, int len)
{
    qtBio * ptr = reinterpret_cast< qtBio*>( bio->ptr );

    return  ptr->write( p, len );;
}

int qtBio::bread(BIO * bio, char * p , int len)
{
    qtBio * ptr = reinterpret_cast< qtBio*>( bio->ptr );
    return ptr->read( p, len );
}

int qtBio::bputs(BIO * bio, const char * p)
{
    qtBio * ptr = reinterpret_cast< qtBio*>( bio->ptr );
    return ptr->write(p);
}

int qtBio::bgets(BIO * bio, char * p, int len)
{
    return ptr->readToNul(p,len);
}

long qtBio::ctrl(BIO *, int, long, void *)
{
    return -1;
}

int qtBio::create(BIO * bio)
{
    qtBio * ptr = new qtBio(bio);
    return 0;
}

int qtBio::destroy(BIO * bio)
{
    qtBio * ptr = reinterpret_cast< qtBio*>( bio->ptr );
    delete ptr;
    return 0;
}

long qtBio::callback_ctrl(BIO *, int, bio_info_cb *)
{
    return -1;
}

long qtBio::callback(struct bio_st * bio,int mode,const char * argp,int argi, long argl,long ret)
{
    return -1;
}

