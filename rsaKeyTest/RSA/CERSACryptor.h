//
//  CERSACryptor.h
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/18.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CERSAKey.h"

@interface CERSACryptor : NSObject

@property(nonatomic, strong) CERSAKey *rsaKey;

-(instancetype)initWithKeys:(CERSAKey*)key;

- (NSString*)rsaEncryptString:(NSString*)string;
- (NSString*)rsaDecryptString:(NSString*)string;

@end
