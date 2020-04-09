#import <Foundation/Foundation.h>

@interface com_codename1_fingerprint_impl_InternalFingerprintImpl : NSObject {
}

-(BOOL)isAvailable;
-(void)scan:(NSString *)reason;
-(BOOL)isSupported;
-(void)addPassword:(int)requestId param1:(NSString*)reason param2:(NSString*)account param3:(NSString*)password;
-(void)deletePassword:(int)requestId param1:(NSString*)reason param2:(NSString*)account;
-(void)getPassword:(int)requestId param1:(NSString*)reason param2:(NSString*)account;

@end
