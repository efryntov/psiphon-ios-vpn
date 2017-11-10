/*
 Copyright (c) 2011, Oliver Drobnik All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 - Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 - Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//
//  DTASN1Parser.m
//  ssltest
//
//  Created by Oliver Drobnik on 19.02.12.
//  Copyright (c) 2012 Cocoanetics. All rights reserved.
//

#import "DTASN1Parser.h"

@implementation DTASN1Parser
{
    NSUInteger _location;
    NSUInteger _endLocation;
    NSUInteger _parseLevel;

    NSError *_parserError;
    BOOL _abortParsing;

    NSDateFormatter *_UTCFormatter;

    // lookup bitmask what delegate methods are implemented
    struct
    {
        unsigned int delegateSupportsString:1;
        unsigned int delegateSupportsInteger:1;
        unsigned int delegateSupportsDataRange:1;
        unsigned int delegateSupportsBitStringRange:1;
        unsigned int delegateSupportsNumber:1;
        unsigned int delegateSupportsNull:1;
        unsigned int delegateSupportsError:1;
        unsigned int delegateSupportsDate:1;
        unsigned int delegateSupportsObjectIdentifier:1;

    } _delegateFlags;

    __weak id <DTASN1ParserDelegate> _delegate;
}

- (id)init {
    self = [super init];

    if (self) {
        _fileHandle = nil;
        _location = NSNotFound;

        // has to end with Z
        _UTCFormatter = [[NSDateFormatter alloc] init];
        _UTCFormatter.dateFormat = @"yyMMddHHmmss'Z'";
        _UTCFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        _UTCFormatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    }

    return self;
}

#pragma mark Parsing
- (void)_parseErrorEncountered:(NSString *)errorMsg
{
    _abortParsing = YES;

    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errorMsg forKey:NSLocalizedDescriptionKey];
    _parserError = [NSError errorWithDomain:@"DTASN1ParserDomain" code:1 userInfo:userInfo];

    if (_delegateFlags.delegateSupportsError)
    {
        [_delegate parser:self parseErrorOccurred:_parserError];
    }
}

- (NSUInteger)_parseLengthAtLocation:(NSUInteger)location lengthOfLength:(NSUInteger *)lengthOfLength
{
    NSUInteger retValue = 0;
    NSUInteger currentLocation = location;

    uint8_t buffer;
    [self.fileHandle seekToFileOffset:location];
    NSData *data = [self.fileHandle readDataOfLength:1];
    if(!data || data.length != 1) {
        [self _parseErrorEncountered:@"Could not read data of length"];
        return 0;
    }


    buffer = *(const uint8_t*)[data bytes];
    currentLocation++;

    if (buffer<0x80)
    {
        retValue = (NSUInteger)buffer;
    }
    else if (buffer>0x80)
    {
        // next n bytes describe the length length
        NSUInteger lengthLength = buffer-0x80;
        NSRange lengthRange = NSMakeRange(currentLocation,lengthLength);

        if (NSMaxRange(lengthRange)> _endLocation)
        {
            [self _parseErrorEncountered:@"Invalid length encountered"];
            return 0;
        }

        // get the length bytes
        uint8_t *lengthBytes;
        [self.fileHandle seekToFileOffset:lengthRange.location];
        NSData *data = [self.fileHandle readDataOfLength:lengthLength];
        if(!data || data.length != lengthLength) {
            [self _parseErrorEncountered:@"Could not read data of length"];
            return 0;
        }

        lengthBytes = (uint8_t*)[data bytes];
        currentLocation += lengthLength;

        for (int i=0; i<lengthLength;i++)
        {
            // shift previous
            retValue <<= 8;

            // add the new byte
            retValue += lengthBytes[i];
        }
    }
    else
    {
        // length 0x80 means "indefinite"
        [self _parseErrorEncountered:@"Indefinite Length form encounted, not implemented"];
    }

    if (lengthOfLength)
    {
        *lengthOfLength = currentLocation - location;
    }

    return retValue;
}

- (BOOL)_parseValueWithTag:(NSUInteger)tag dataRange:(NSRange)dataRange
{
    if (!dataRange.length)
    {
        // only NULL and strings can have zero length

        switch (tag)
        {
            case DTASN1TypeNull:
            case DTASN1TypeTeletexString:
            case DTASN1TypeGraphicString:
            case DTASN1TypePrintableString:
            case DTASN1TypeUTF8String:
            case DTASN1TypeIA5String:
                break;
            default:
                return NO;
        }
    }

    switch (tag)
    {
        case DTASN1TypeBoolean:
        {
            if (dataRange.length!=1)
            {
                [self _parseErrorEncountered:@"Illegal length of Boolean value"];
                return NO;
            }

            if (_delegateFlags.delegateSupportsNumber)
            {
                uint8_t boolByte;
                [self.fileHandle seekToFileOffset:dataRange.location];
                NSData *data = [self.fileHandle readDataOfLength:1];
                if(!data || data.length != 1) {
                    [self _parseErrorEncountered:@"Could not read data of length"];
                    return NO;
                }

                boolByte = *(const uint8_t*)[data bytes];

                BOOL b = boolByte!=0;

                NSNumber *number = [NSNumber numberWithBool:b];
                [_delegate parser:self foundNumber:number];
            }
            break;
        }

        case DTASN1TypeInteger:
        {
            BOOL sendAsData = NO;

            if (dataRange.length <= sizeof(unsigned long long))
            {
                uint8_t *buffer;
                [self.fileHandle seekToFileOffset:dataRange.location];
                NSData *data = [self.fileHandle readDataOfLength:dataRange.length];
                if(!data || data.length != dataRange.length) {
                    [self _parseErrorEncountered:@"Could not read data of length"];
                    return NO;
                }

                buffer = (uint8_t*)[data bytes];

                if (_delegateFlags.delegateSupportsNumber)
                {
                    unsigned long long value = 0;

                    for (int i=0; i<dataRange.length; i++)
                    {
                        value <<=8;
                        value += buffer[i];
                    }

                    NSNumber *number = [NSNumber numberWithUnsignedLongLong:value];

                    [_delegate parser:self foundNumber:number];
                }
                else
                {
                    // send number as data if supported, too long for 32 bit
                    sendAsData = YES;
                }
            }
            else
            {
                // send number as data if supported, delegate does not want numbers
                sendAsData = YES;
            }

            if (sendAsData && _delegateFlags.delegateSupportsDataRange)
            {
                [_delegate parser:self foundDataRange:dataRange];
            }

            break;
        }

        case DTASN1TypeBitString:
        {
            if (_delegateFlags.delegateSupportsBitStringRange)
            {
                [_delegate parser:self foundBitStringRange:dataRange];
            }

            break;
        }

        case DTASN1TypeOctetString:
        {
            if (_delegateFlags.delegateSupportsDataRange)
            {
                [_delegate parser:self foundDataRange:dataRange];
            }

            break;
        }

        case DTASN1TypeNull:
        {
            if (_delegateFlags.delegateSupportsNull)
            {
                [_delegate parserFoundNull:self];
            }

            break;
        }

        case DTASN1TypeObjectIdentifier:
        {
            if (_delegateFlags.delegateSupportsObjectIdentifier)
            {
                NSMutableArray *indexes = [NSMutableArray array];

                uint8_t *buffer;
                [self.fileHandle seekToFileOffset:dataRange.location];
                NSData *data = [self.fileHandle readDataOfLength:dataRange.length];
                if(!data || data.length != dataRange.length) {
                    [self _parseErrorEncountered:@"Could not read data of length"];
                    return NO;
                }

                buffer = (uint8_t*)[data bytes];

                // first byte is different
                [indexes addObject:[NSNumber numberWithUnsignedInteger:buffer[0]/40]];
                [indexes addObject:[NSNumber numberWithUnsignedInteger:buffer[0]%40]];

                for (int i=1; i<dataRange.length; i++)
                {
                    NSUInteger value=0;

                    BOOL more = NO;
                    do
                    {
                        uint8_t b = buffer[i];
                        value = value * 128;
                        value += (b & 0x7f);

                        more = ((b & 0x80) == 0x80);

                        if (more)
                        {
                            i++;
                        }

                        if (i==dataRange.length && more)
                        {
                            [self _parseErrorEncountered:@"Invalid object identifier with more bit set on last octed"];
                            return NO;
                        }
                    } while (more);

                    [indexes addObject:[NSNumber numberWithUnsignedInteger:value]];
                }

                NSString *joinedComponents = [indexes componentsJoinedByString:@"."];
                [_delegate parser:self foundObjectIdentifier:joinedComponents];
            }

            break;
        }

        case DTASN1TypeTeletexString:
        case DTASN1TypeGraphicString:
        case DTASN1TypePrintableString:
        case DTASN1TypeUTF8String:
        case DTASN1TypeIA5String:
        {
            if (_delegateFlags.delegateSupportsString)
            {
                NSString *string = @"";
                uint8_t *buffer = NULL;

                if (dataRange.length)
                {
                    [self.fileHandle seekToFileOffset:dataRange.location];
                    NSData *data = [self.fileHandle readDataOfLength:dataRange.length];
                    if(!data || data.length != dataRange.length) {
                        [self _parseErrorEncountered:@"Could not read data of length"];
                        return NO;
                    }

                    buffer = (uint8_t*)[data bytes];

                    string = [[NSString alloc] initWithBytesNoCopy:buffer length:dataRange.length encoding:NSUTF8StringEncoding freeWhenDone:NO];
                }

                // FIXME: This does not properly deal with Latin1 strings, those get simply ignored

                if (string)
                {
                    [_delegate parser:self foundString:string];
                }
                else
                {
                    if (buffer)
                    {
                        buffer = NULL;
                    }
                }
            }
            break;
        }

        case DTASN1TypeUTCTime:
        case DTASN1TypeGeneralizedTime:
        {
            if (_delegateFlags.delegateSupportsDate)
            {
                uint8_t *buffer;
                [self.fileHandle seekToFileOffset:dataRange.location];
                NSData *data = [self.fileHandle readDataOfLength:dataRange.length];
                if(!data || data.length != dataRange.length) {
                    [self _parseErrorEncountered:@"Could not read data of length"];
                    return NO;
                }

                buffer = (uint8_t*)[data bytes];

                NSString *string = [[NSString alloc] initWithBytesNoCopy:buffer length:dataRange.length encoding:NSASCIIStringEncoding freeWhenDone:NO];

                NSDate *parsedDate = [_UTCFormatter dateFromString:string];

                if (parsedDate)
                {
                    [_delegate parser:self foundDate:parsedDate];
                }
                else
                {
                    NSString *msg = [NSString stringWithFormat:@"Cannot parse date '%@'", string];
                    [self _parseErrorEncountered:msg];
                    return NO;
                }
            }

            break;
        }

        default:
        {
            NSString *msg = [NSString stringWithFormat:@"Tag of type %ld not implemented", (unsigned long)tag];
            [self _parseErrorEncountered:msg];
            return NO;
        }
    }

    return YES;
}

- (BOOL)_parseRange
{
    _parseLevel++;


    if (_abortParsing)
    {
        return NO;
    }

    // get type
    uint8_t tagByte;
    [self.fileHandle seekToFileOffset:_location];
    NSData *data = [self.fileHandle readDataOfLength:1];
    if(!data || data.length != 1) {
        return NO;
    }
    tagByte = *(const uint8_t*)[data bytes];
    _location++;

    NSUInteger tagClass = tagByte >> 6;
    DTASN1Type tagType = tagByte & 31;
    BOOL tagConstructed = (tagByte >> 5) & 1;

    if (tagType == DTASN1TypeUsesLongForm)
    {
        [self _parseErrorEncountered:@"Long form not implemented"];
        return NO;
    }

    // get length
    NSUInteger lengthOfLength = 0;
    NSUInteger length = [self _parseLengthAtLocation:_location lengthOfLength:&lengthOfLength];

    // abort if there was a problem with the length
    if (_parserError)
    {
        return NO;
    }

    _location += lengthOfLength;

    // make range
    NSRange subRange = NSMakeRange(_location, length);

    if (NSMaxRange(subRange) > _endLocation)
    {
        return NO;
    }
    if (tagClass == 2)
    {
        if (!tagConstructed)
        {
            tagType = DTASN1TypeOctetString;
        }
    }

    if (tagConstructed)
    {
        // allow for sequence without content
        if (subRange.length > 0)
        {
            return YES;
        }
    }
    else
    {
        // primitive
        if (![self _parseValueWithTag:tagType dataRange:subRange])
        {
            _abortParsing = YES;
        }
    }

    // advance
    _location += length;

    _parseLevel--;

    return YES;
}

- (BOOL)parseRange:(NSRange)range withFileHandle:(NSFileHandle*)fileHandle;
{

    _fileHandle = fileHandle;
    _location = range.location;
    _endLocation = NSMaxRange(range);

    BOOL result = NO;
    do {
        @autoreleasepool
        {
            result = [self _parseRange];
            if(!result || _abortParsing) {
                break;
            }
        }
    } while(_location < _endLocation);

    return result;
}

- (void)abortParsing
{
    _abortParsing = YES;
}

#pragma mark Properties

- (id <DTASN1ParserDelegate>)delegate
{
    return _delegate;
}

- (void)setDelegate:(id <DTASN1ParserDelegate>)delegate;
{
    _delegate = delegate;

    if ([_delegate respondsToSelector:@selector(parser:parseErrorOccurred:)])
    {
        _delegateFlags.delegateSupportsError = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundString:)])
    {
        _delegateFlags.delegateSupportsString = YES;
    }

    if ([_delegate respondsToSelector:@selector(parserFoundNull:)])
    {
        _delegateFlags.delegateSupportsNull = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundDate:)])
    {
        _delegateFlags.delegateSupportsDate = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundDataRange:)])
    {
        _delegateFlags.delegateSupportsDataRange = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundBitStringRange:)])
    {
        _delegateFlags.delegateSupportsBitStringRange = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundNumber:)])
    {
        _delegateFlags.delegateSupportsNumber = YES;
    }

    if ([_delegate respondsToSelector:@selector(parser:foundObjectIdentifier:)])
    {
        _delegateFlags.delegateSupportsObjectIdentifier = YES;
    }
}

@synthesize parserError = _parserError;

@end
