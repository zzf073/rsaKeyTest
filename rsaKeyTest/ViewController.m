//
//  ViewController.m
//  rsaKeyTest
//
//  Created by zzf073 on 15/12/17.
//  Copyright (c) 2015年 zzf073. All rights reserved.
//

#import "ViewController.h"
#import "CERSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    [self encryptTest];
    
    [self mySignTest];
}

-(void)encryptTest
{
    CERSAKey *rsaKey = [[CERSAKey alloc] init];
    
    NSString *derPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"];
    [rsaKey loadPublicKeyFromFile:derPath];
    
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"];
    [rsaKey loadPrivateKeyFromFile:p12Path password:@"111111"];
    
    CERSACryptor *cryptor = [[CERSACryptor alloc] initWithKeys:rsaKey];
    
    NSString *test = @"rsaKey loadPrivateKeyFromFile:p12Path";
    
    NSString *rt = [cryptor rsaEncryptString:test];
    
    NSString *drt = [cryptor rsaDecryptString:rt];
    
    NSLog(@"%@", drt);
}

-(void)mySignTest
{
    CERSAKey *rsaKey = [[CERSAKey alloc] init];
    
    NSString *derPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"der"];
    [rsaKey loadPublicKeyFromFile:derPath];
    
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"private_key" ofType:@"p12"];
    [rsaKey loadPrivateKeyFromFile:p12Path password:@"111111"];
    
    CERSASign *rsaSign = [[CERSASign alloc] initWithKeys:rsaKey];
    
    NSString *enStr = @"ihep_这是用于签名的原始数据";
    
    NSData *enData = [enStr dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *signData = [rsaSign rsaSHA1SignData:enStr];
    
    NSLog(@"签名后的base64:%@",[CEBase64 base64forData:signData]);
    
    BOOL signSuccess = [rsaSign rsaSHA1VerifyData:enData withSignature:signData];//[self.rsaCryptor rsaSHA256VerifyData:enData withSignature:signData];
    NSLog(@"是否签名成功：%@",signSuccess ? @"是":@"否");
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
