
#import <Foundation/Foundation.h>
#import "DTASN1Parser.h"

@interface SlimAppReceipt : NSObject <DTASN1ParserDelegate>

@property (nonatomic, strong, readonly) NSData *bundleIdentifierData;
@property (nonatomic, strong, readonly) NSString *bundleIdentifier;
@property (nonatomic, strong, readonly) NSData *receiptHash;
@property (nonatomic, strong, readonly) NSData *opaqueValue;
@property (nonatomic, strong, readonly) NSDictionary *inAppPurchases;

+ (instancetype)bundleReceipt;
- (BOOL)parseReceipt:(NSRange)range withFileHandle:(NSFileHandle*)fh;
- (BOOL)verifyReceiptHash;
- (NSDate*)expirationDateForProduct:(NSString*)productIdentifier;

@end
