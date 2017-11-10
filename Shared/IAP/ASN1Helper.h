
#import <Foundation/Foundation.h>
#import "DTASN1Parser.h"

@interface ASN1Helper : NSObject <DTASN1ParserDelegate>

-(instancetype) initWithFileHandle:(NSFileHandle*)fileHandle;
- (NSString*)getString:(NSRange)range error:(NSError **)error;
- (NSNumber*)getNumber:(NSRange)range error:(NSError **)error;
- (NSDate*)getDate:(NSRange)range error:(NSError **)error;
@end


