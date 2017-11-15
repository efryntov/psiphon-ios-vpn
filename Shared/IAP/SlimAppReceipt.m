//
//  PKCS7Payload.m
//  appReceiptSlim
//
//  Created by eugene-imac on 2017-11-08.
//  Copyright © 2017 Psiphon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SlimAppReceipt.h"
#import "PKCS7Payload.h"
#import "ASN1Helper.h"
#import "SlimIAPReceipt.h"
#import "SlimIAPReceipt.h"
#import <CommonCrypto/CommonDigest.h>


@implementation SlimAppReceipt {
    NSFileHandle *_fileHandle;
    DTASN1Parser *_parser;
    NSUInteger _sequenceField1;
    NSRange _sequenceField3;
    int _sequenceOrder;
    NSMutableDictionary *_parsedIAPs;
    SlimIAPReceipt *_currentIAPReceipt;
    ASN1Helper *_asn1Helper;
}

- (id)init {
    self = [super init];
    
    if (self) {
        _sequenceOrder = 0;
        _parser = [[DTASN1Parser alloc] init];
        _parser.delegate = self;
        _parsedIAPs = [[NSMutableDictionary alloc] init];
        _currentIAPReceipt = [[SlimIAPReceipt alloc] init];
    }
    return self;
}

+ (instancetype)bundleReceipt {
    NSURL *URL = [NSBundle mainBundle].appStoreReceiptURL;
    NSString *path = URL.path;
    const BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:nil];
    if (!exists) return nil;
    
    NSUInteger length = 0;
    NSNumber *fileSizeValue = nil;
    
    NSError *fileSizeError = nil;
    [URL getResourceValue:&fileSizeValue
                   forKey:NSURLFileSizeKey
                    error:&fileSizeError];
    if (!fileSizeValue) {
        return nil;
    }
    
    length = [fileSizeValue unsignedIntegerValue];
    
    NSError *error = nil;
    NSFileHandle* fh = [NSFileHandle fileHandleForReadingFromURL:URL error:&error];
    if (error) {
        return nil;
    }
    
    NSRange fileRange = NSMakeRange(0, length);
    
    PKCS7Payload *pkcs7data = [[PKCS7Payload alloc] init];
    NSRange pkcs7Range = [pkcs7data rangeFrom:fileRange withFileHandle:fh];
    pkcs7data = nil;
    
    SlimAppReceipt *appReceipt = [[SlimAppReceipt alloc] init];
    
    if (![appReceipt parseReceipt:pkcs7Range withFileHandle:fh]) {
        appReceipt = nil;
    }
    
    [fh closeFile];
    return appReceipt;
}


- (BOOL)parseReceipt:(NSRange)range withFileHandle:(NSFileHandle*)fh {
    _asn1Helper = [[ASN1Helper alloc] initWithFileHandle:fh];
    BOOL result =  [_parser parseRange:range withFileHandle:fh];
    
    if(result) {
        result = [self verifyReceiptHash];
    }
    
    if(result) {
        _inAppPurchases = _parsedIAPs;
    }
    
    return result;
}

- (void) processReceiptSequence {
    NSUInteger type = _sequenceField1;
    NSRange range = _sequenceField3;
    
    NSError * error = nil;
    switch (type) {
        case 2:
            // bundleIdentifier
            [_parser.fileHandle seekToFileOffset:range.location];
            _bundleIdentifierData = [_parser.fileHandle readDataOfLength:range.length];
            _bundleIdentifier = [_asn1Helper getString:range error:&error];
            break;
        case 4:
            // opaqueValue
            [_parser.fileHandle seekToFileOffset:range.location];
            _opaqueValue = [_parser.fileHandle readDataOfLength:range.length];
            break;
        case 5:
            // receiptHash
            [_parser.fileHandle seekToFileOffset:range.location];
            _receiptHash = [_parser.fileHandle readDataOfLength:range.length];
            break;
        case 17: {
            SlimIAPReceipt *iap = _currentIAPReceipt;
            if(![iap parseReceipt:range withFileHandle:_parser.fileHandle]) {
                break;
            }
            
            //Apple: treat a canceled receipt the same as if no purchase had ever been made.
            if(iap.cancellationDate) {
                break;
            }
            
            // sanity check
            if(iap.subscriptionExpirationDate == nil || iap.productIdentifier == nil) {
                break;
            }
            
            NSDate *subscriptionExpirationDate = [_parsedIAPs objectForKey:iap.productIdentifier];
            if (!subscriptionExpirationDate) {
                [_parsedIAPs setObject:iap.subscriptionExpirationDate forKey:iap.productIdentifier];
            } else {
                if ([subscriptionExpirationDate compare:iap.subscriptionExpirationDate] == NSOrderedAscending) {
                    [_parsedIAPs setObject:iap.subscriptionExpirationDate forKey:iap.productIdentifier];
                }
            }
        }
        default:
            break;
    }
}

- (BOOL)verifyReceiptHash {
    NSUUID *uuid = [UIDevice currentDevice].identifierForVendor;
    unsigned char uuidBytes[16];
    [uuid getUUIDBytes:uuidBytes];
    
    // Order taken from: https://developer.apple.com/library/ios/releasenotes/General/ValidateAppStoreReceipt/Chapters/ValidateLocally.html#//apple_ref/doc/uid/TP40010573-CH1-SW5
    NSMutableData *data = [NSMutableData data];
    [data appendBytes:uuidBytes length:sizeof(uuidBytes)];
    [data appendData:self.opaqueValue];
    [data appendData:self.bundleIdentifierData];
    
    NSMutableData *expectedHash = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1((const uint8_t*)data.bytes, (CC_LONG)data.length, (uint8_t*)expectedHash.mutableBytes); // Explicit casting to avoid errors when compiling as Objective-C++
    
    return [expectedHash isEqualToData:self.receiptHash];
}

- (NSDate*)expirationDateForProduct:(NSString*)productIdentifier {
    return [self.inAppPurchases objectForKey:productIdentifier];
}

# pragma mark DTASN1ParserDelegate methods

- (void)parser:(DTASN1Parser *)parser foundDataRange:(NSRange)dataRange {
    if(_sequenceOrder == 2) {
        _sequenceField3 = dataRange;
        [self processReceiptSequence];
        _sequenceOrder = 0;
    }
}

- (void)parser:(DTASN1Parser *)parser foundNumber:(NSNumber *)number {
    if(_sequenceOrder == 0) {
        _sequenceField1 = [number unsignedIntegerValue];
    }
    _sequenceOrder ++;
}

@end

