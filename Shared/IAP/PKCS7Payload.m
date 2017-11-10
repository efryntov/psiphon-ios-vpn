//
//  PKCS7Payload.m
//  appReceiptSlim
//
//  Created by eugene-imac on 2017-11-08.
//  Copyright © 2017 Psiphon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PKCS7Payload.h"

@implementation PKCS7Payload {
    BOOL _foundPKCS7Payload;
    NSRange _pksc7Range;
    DTASN1Parser *_parser;
}

- (id)init {
    self = [super init];
    
    if (self) {
        _foundPKCS7Payload = NO;
        _pksc7Range = NSMakeRange(NSNotFound, 0);
        _parser = [[DTASN1Parser alloc] init];
        _parser.delegate = self;
    }
    return self;
}


- (NSRange)rangeFrom:(NSRange)range withFileHandle:(NSFileHandle*)fh {
    [_parser parseRange:range withFileHandle:fh];
    return _pksc7Range;
}

- (void)parser:(DTASN1Parser *)parser foundObjectIdentifier:(NSString *)objIdentifier {
    if([objIdentifier isEqualToString:@"1.2.840.113549.1.7.1"]) {
        _foundPKCS7Payload = YES;
    }
}
- (void)parser:(DTASN1Parser *)parser foundDataRange:(NSRange)dataRange {
    if(_foundPKCS7Payload) {
        _pksc7Range = dataRange;
        [parser abortParsing];
    }
}
@end
