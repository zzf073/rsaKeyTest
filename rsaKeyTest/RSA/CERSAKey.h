//
//  CERSAKey.h
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CERSAKey : NSObject

@property(nonatomic, readonly) SecKeyRef publicKey;

@property(nonatomic, readonly) SecKeyRef privateKey;

- (void)loadPublicKeyFromFile:(NSString*)derFilePath;
- (void)loadPublicKeyFromData:(NSData*)derData;

- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password;
- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password;

@end
