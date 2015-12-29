//
//  CERSAKey.m
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import "CERSAKey.h"

@implementation CERSAKey
{
    SecKeyRef xpublicKey;
    SecKeyRef xprivateKey;
}

#pragma mark - Private Methods

- (void)dealloc {
    if (xpublicKey)
        CFRelease(xpublicKey);
    
    if (!xprivateKey)
        CFRelease(xprivateKey);
}

- (SecKeyRef)publicKey {
    return xpublicKey;
}

- (SecKeyRef)privateKey {
    return xprivateKey;
}

#pragma mark - Public Methods

- (void)loadPublicKeyFromFile:(NSString*)derFilePath {
    
    NSData *derData = [[NSData alloc] initWithContentsOfFile:derFilePath];
    [self loadPublicKeyFromData:derData];
}

- (void)loadPublicKeyFromData:(NSData*)derData {
    xpublicKey = [self getPublicKeyRefrenceFromeData: derData];
}

- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password {
    
    NSData *p12Data = [NSData dataWithContentsOfFile:p12FilePath];
    [self loadPrivateKeyFromData: p12Data password:p12Password];
}

- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password {
    xprivateKey = [self getPrivateKeyRefrenceFromData: p12Data password: p12Password];
}

- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData*)derData {
    
    SecCertificateRef myCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)derData);
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();
    SecTrustRef myTrust;
    OSStatus status = SecTrustCreateWithCertificates(myCertificate,myPolicy,&myTrust);
    SecTrustResultType trustResult;
    if (status == noErr) {
        status = SecTrustEvaluate(myTrust, &trustResult);
    }
    SecKeyRef securityKey = SecTrustCopyPublicKey(myTrust);
    CFRelease(myCertificate);
    CFRelease(myPolicy);
    CFRelease(myTrust);
    
    //xpublicKey = securityKey;
    
    return securityKey;
}

- (SecKeyRef)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password {
    
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    //xprivateKey = privateKeyRef;
    
    return privateKeyRef;
}


@end
