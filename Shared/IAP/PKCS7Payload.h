
#import <Foundation/Foundation.h>
#import "DTASN1Parser.h"

@interface PKCS7Payload : NSObject <DTASN1ParserDelegate>
- (NSRange)rangeFrom:(NSRange)range withFileHandle:(NSFileHandle*)fh;
@end

