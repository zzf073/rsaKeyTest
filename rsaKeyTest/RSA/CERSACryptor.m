//
//  CERSACryptor.m
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import "CERSACryptor.h"
#import "CEBase64.h"

@interface CERSACryptor()

@end

@implementation CERSACryptor

-(instancetype)initWithKeys:(CERSAKey*)key
{
    if(self = [super init])
    {
        self.rsaKey = key;
    }
    
    return self;
}

- (NSString*)rsaEncryptString:(NSString*)string {
    
    NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData* encryptedData = [self rsaEncryptData: data];
    NSString *base64EncryptedString = [CEBase64 base64forData:encryptedData];
    NSLog(@"%@", base64EncryptedString);
    //[GTMBase64 stringByEncodingData:encryptedData];
    return base64EncryptedString;
}


- (NSData*)rsaEncryptData:(NSData*)data {
    SecKeyRef key = self.rsaKey.publicKey;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    
    NSMutableData *encryptedData = [[NSMutableData alloc] init];
    
    for (int i=0; i<blockCount; i++) {
        unsigned long bufferSize = MIN(blockSize , [data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        
        OSStatus status = SecKeyEncrypt(key,
                                        kSecPaddingPKCS1,
                                        (const uint8_t *)[buffer bytes],
                                        [buffer length],
                                        cipherBuffer,
                                        &cipherBufferSize);
        
        if (status != noErr) {
            return nil;
        }
        
        NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
        [encryptedData appendData:encryptedBytes];
    }
    
    if (cipherBuffer){
        free(cipherBuffer);
    }
    
    return encryptedData;
}


#pragma mark  Decrypt

- (NSString*)rsaDecryptString:(NSString*)string {
    
    NSData* data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData* decryptData = [self rsaDecryptData:data];
    NSString* result = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    return result;
}

- (NSData*)rsaDecryptData:(NSData*)data {
    SecKeyRef key = self.rsaKey.privateKey;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    size_t blockSize = cipherBufferSize;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    
    NSMutableData *decryptedData = [[NSMutableData alloc] init];
    
    for (int i = 0; i < blockCount; i++) {
        unsigned long bufferSize = MIN(blockSize , [data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        
        size_t cipherLen = [buffer length];
        void *cipher = malloc(cipherLen);
        [buffer getBytes:cipher length:cipherLen];
        size_t plainLen = SecKeyGetBlockSize(key);
        void *plain = malloc(plainLen);
        
        OSStatus status = SecKeyDecrypt(key,
                                        kSecPaddingPKCS1,
                                        cipher,
                                        cipherLen,
                                        plain,
                                        &plainLen);
        
        if (status != noErr) {
            return nil;
        }
        
        NSData *decryptedBytes = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
        [decryptedData appendData:decryptedBytes];
    }
    
    return decryptedData;
}

@end
