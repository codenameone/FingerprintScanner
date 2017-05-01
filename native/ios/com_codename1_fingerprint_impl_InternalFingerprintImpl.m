#import "com_codename1_fingerprint_impl_InternalFingerprintImpl.h"
#include "com_codename1_fingerprint_impl_InternalCallback.h"

#import <LocalAuthentication/LocalAuthentication.h>

@implementation com_codename1_fingerprint_impl_InternalFingerprintImpl


-(BOOL)isAvailable{
    if (NSClassFromString(@"LAContext") == NULL) {
        return NO;
    }
    
    NSError *error = nil;
    LAContext *laContext = [[LAContext alloc] init];
    
    return [laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
}


-(void)scan{
    dispatch_async(dispatch_get_main_queue(), ^{
        LAContext *context = [[LAContext alloc] init];
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"Authenticate for server login" reply:^(BOOL success, NSError *authenticationError){
            if (success) {
                com_codename1_fingerprint_impl_InternalCallback_scanSuccess__(getThreadLocalData());
            }
            else {
                com_codename1_fingerprint_impl_InternalCallback_scanFail__(getThreadLocalData());
            }
        }];
    });
}

-(BOOL)isSupported{
    return YES;
}

@end
