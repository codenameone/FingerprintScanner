#import <Foundation/Foundation.h>

@interface com_codename1_fingerprint_impl_InternalFingerprintImpl : NSObject {
}

-(BOOL)isAvailable;
-(void)scan;
-(void)scan:(NSString *)reason;
-(BOOL)isSupported;
@end
