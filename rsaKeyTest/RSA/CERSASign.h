//
//  CERSASign.h
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CERSAKey.h"

@interface CERSASign : NSObject

-(instancetype)initWithKeys:(CERSAKey*)key;

@property(nonatomic, strong) CERSAKey *rsaKey;

- (NSData *)rsaSHA256SignData:(NSData *)plainData;
- (BOOL)rsaSHA256VerifyData:(NSData *)plainData withSignature:(NSData *)signature;

-(NSData *)rsaSHA1SignData:(NSString *)plainText;
- (BOOL)rsaSHA1VerifyData:(NSData *)plainData withSignature:(NSData *)signature;

@end
