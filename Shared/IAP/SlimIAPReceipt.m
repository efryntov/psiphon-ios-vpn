//
//  PKCS7Payload.m
//  appReceiptSlim
//
//  Created by eugene-imac on 2017-11-08.
//  Copyright © 2017 Psiphon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SlimIAPReceipt.h"
#import "ASN1Helper.h"

@implementation SlimIAPReceipt {
    NSFileHandle *_fileHandle;
    DTASN1Parser *_parser;
    NSUInteger _sequenceField1;
    NSRange _sequenceField3;
    int _sequenceOrder;
    ASN1Helper *_asn1Helper;
}

- (id)init {
    self = [super init];
    
    if (self) {
        _sequenceOrder = 0;
        _parser = [[DTASN1Parser alloc] init];
        _parser.delegate = self;
    }
    return self;
}


- (BOOL)parseReceipt:(NSRange)range withFileHandle:(NSFileHandle*)fh {
    _asn1Helper = [[ASN1Helper alloc] initWithFileHandle:fh];
    return [_parser parseRange:range withFileHandle:fh];
}

- (void) processReceiptSequence {
    NSUInteger type = _sequenceField1;
    NSRange range = _sequenceField3;
    
    NSError * error = nil;
    switch (type) {
        case 1702:
            // productIdentifier
            _productIdentifier = [_asn1Helper getString:range error:&error];
            break;
        case 1708:
            // subscriptionExpirationDate
            _subscriptionExpirationDate = [_asn1Helper getDate:range error:&error];
            break;
        case 1712:
            // cancellationDate
            _cancellationDate = [_asn1Helper getDate:range error:&error];
            break;
        default:
            break;
    }
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
