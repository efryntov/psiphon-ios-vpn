//
//  PKCS7Payload.m
//  appReceiptSlim
//
//  Created by eugene-imac on 2017-11-08.
//  Copyright © 2017 Psiphon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Helper.h"

@implementation ASN1Helper {
    id _value;
    DTASN1Parser *_parser;
    NSFileHandle *_fileHandle;
}

- (id)initWithFileHandle:(NSFileHandle *)fileHandle {
    self = [super init];
    
    if (self) {
        _fileHandle = fileHandle;
        _parser = [[DTASN1Parser alloc] init];
        _parser.delegate = self;
    }
    return self;
}

- (NSString*)getString:(NSRange)range error:(NSError **)error {
    _value = nil;
    [_parser parseRange:range withFileHandle:_fileHandle];
    if([_value isKindOfClass:[NSString class]]) {
        return (NSString*)_value;
    }
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"Unexpected value type, expecting NSString" forKey:NSLocalizedDescriptionKey];
    *error = [NSError errorWithDomain:@"ASN1Helper" code:1 userInfo:userInfo];
    return nil;
}

- (NSNumber*)getNumber:(NSRange)range error:(NSError **)error {
    _value = nil;
    [_parser parseRange:range withFileHandle:_fileHandle];
    if([_value isKindOfClass:[NSNumber class]]) {
        return (NSNumber*)_value;
    }
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"Unexpected value type, expecting NSNumber" forKey:NSLocalizedDescriptionKey];
    *error = [NSError errorWithDomain:@"ASN1Helper" code:1 userInfo:userInfo];
    return nil;
}

+ (NSDate*)formatRFC3339String:(NSString*)string {
    static NSDateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZ";
    });
    NSDate *date = [formatter dateFromString:string];
    return date;
}

- (NSDate*)getDate:(NSRange)range error:(NSError **)error {
    _value = nil;
    [_parser parseRange:range withFileHandle:_fileHandle];
    if([_value isKindOfClass:[NSString class]]) {
        NSString* dateString = (NSString*)_value;
        if([dateString length]) {
            NSDate *parsedDate = [ASN1Helper formatRFC3339String:dateString];
            if(parsedDate) {
                return parsedDate;
            } else {
                NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"Could not parse date string" forKey:NSLocalizedDescriptionKey];
                *error = [NSError errorWithDomain:@"ASN1Helper" code:1 userInfo:userInfo];
                return nil;
            }
        } else {
            return nil;
        }
    }
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"Unexpected value type, expecting" forKey:NSLocalizedDescriptionKey];
    *error = [NSError errorWithDomain:@"ASN1Helper" code:1 userInfo:userInfo];
    return nil;
}

- (void)parser:(DTASN1Parser *)parser foundNumber:(NSNumber *)number {
    _value = [number copy];
}

- (void)parser:(DTASN1Parser *)parser foundString:(NSString *)string {
    _value = [string copy];
}

@end

