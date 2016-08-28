#ifndef HMAC_H__
#define HMAC_H__

typedef struct {
    void *hash_context;
    void (*hash_begin)(void *);
    void (*hash_update)(void *, int, const unsigned char *);
    void (*hash_output)(void *, unsigned char *);
    int B;  // byte-length of an internal block of the underlying hash function
    int L;  // byte-length of a hashed result from the underlying hash function
            // for example: L = 32 and B = 64 for SHA-256; note that L <= B
    unsigned char *workingBufferB; // a B-byte buffer for HMAC computation
    unsigned char *workingBufferL; // a L-byte buffer for HMAC computation
} hmac_context_t;

void hmac_begin(const void *, int, const unsigned char *);
void hmac_update(const void *, int, const unsigned char *);
void hmac_output(const void *, unsigned char *);

#endif
