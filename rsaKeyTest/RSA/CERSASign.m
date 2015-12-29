//
//  CERSASign.m
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import "CERSASign.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH

@implementation CERSASign

-(instancetype)initWithKeys:(CERSAKey*)key
{
    if(self = [super init])
    {
        self.rsaKey = key;
    }
    
    return self;
}

- (NSData *)rsaSHA256SignData:(NSData *)plainData {
    SecKeyRef key = self.rsaKey.privateKey;
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(key,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

- (BOOL)rsaSHA256VerifyData:(NSData *)plainData withSignature:(NSData *)signature {
    SecKeyRef key = self.rsaKey.publicKey;
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }
    
    OSStatus status = SecKeyRawVerify(key,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}

-(NSData *)rsaSHA1SignData:(NSString *)plainText
{
    uint8_t* signedBytes = NULL;
    size_t signedBytesSize = 0;
    OSStatus sanityCheck = noErr;
    NSData* signedHash = nil;
    
    SecKeyRef privateKeyRef=self.rsaKey.privateKey;
    
    signedBytesSize = SecKeyGetBlockSize(privateKeyRef);
    
    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    signedBytes = malloc( signedBytesSize * sizeof(uint8_t) ); // Malloc a buffer to hold signature.
    memset((void *)signedBytes, 0x0, signedBytesSize);
    
    sanityCheck = SecKeyRawSign(privateKeyRef,
                                kSecPaddingPKCS1SHA1,
                                (const uint8_t *)[[self getHashBytes:plainTextBytes] bytes],
                                kChosenDigestLength,
                                (uint8_t *)signedBytes,
                                &signedBytesSize);
    
    if (sanityCheck == noErr)
    {
        signedHash = [NSData dataWithBytes:(const void *)signedBytes length:(NSUInteger)signedBytesSize];
    }
    else
    {
        return nil;
    }
    
    if (signedBytes)
    {
        free(signedBytes);
    }
    
    //NSString *signatureResult=[NSString stringWithFormat:@"%@",[signedHash base64EncodedString]];
    
    return signedHash;
}

- (BOOL)rsaSHA1VerifyData:(NSData *)plainData withSignature:(NSData *)signature {
    
    SecKeyRef key = self.rsaKey.publicKey;
    
    size_t signedHashBytesSize = 0;
    OSStatus sanityCheck = noErr;
    
    // Get the size of the assymetric block.
    signedHashBytesSize = SecKeyGetBlockSize(key);
    
    sanityCheck = SecKeyRawVerify(key,
                                  kSecPaddingPKCS1SHA1,
                                  (const uint8_t *)[[self getHashBytes:plainData] bytes],
                                  CC_SHA1_DIGEST_LENGTH,
                                  (const uint8_t *)[signature bytes],
                                  signedHashBytesSize
                                  );
    
    NSLog(@"status %d", (int)sanityCheck);
    
    return (sanityCheck == noErr) ? YES : NO;
}

- (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], (CC_LONG)[plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    
    if (hashBytes) free(hashBytes);
    
    return hash;
}

@end
