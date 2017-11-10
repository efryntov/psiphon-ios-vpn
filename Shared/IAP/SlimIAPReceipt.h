#import <Foundation/Foundation.h>
#import "DTASN1Parser.h"

@interface SlimIAPReceipt : NSObject <DTASN1ParserDelegate>

@property (nonatomic, strong, readonly) NSString *productIdentifier;
@property (nonatomic, strong, readonly) NSDate *subscriptionExpirationDate;
@property (nonatomic, strong, readonly) NSDate *cancellationDate;
- (BOOL)parseReceipt:(NSRange)range withFileHandle:(NSFileHandle*)fh;

@end
