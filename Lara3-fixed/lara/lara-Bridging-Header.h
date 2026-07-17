//
  //  lara-Bridging-Header.h
  //  lara
  //

  @import UIKit;
  #import <Foundation/Foundation.h>

  #import "darksword.h"
#import "pac_utils.h"
#import "OmegaCrashBarrier.h"
  #import "offsets.h"
  #import "utils.h"
  #import "vnode.h"
  #import "apfs.h"
  #import "vfs.h"
  #import "sbx.h"
  #import "amfi.h"
  #import "ppl.h"
  #import "ppl_physmap.h"
  #import "roothunter.h"

  // tools_creds.h defines tool_result_t as an anonymous struct.
  // tools_pac.h and tools_system.h guard it with #ifndef tool_result_t —
  // which only works for preprocessor macros, not typedefs.
  // We define the macro here AFTER tools_creds.h so the guard fires correctly.
  #import "tools_creds.h"
  #define tool_result_t tool_result_t
  #import "tools_pac.h"
  #import "tools_system.h"

  #import "IconServices.h"
  #import "rc.h"
  #import "RemoteCall.h"
  #import "decrypt.h"
  #import "persistence.h"
  #import "ota.h"
  #import "screentime.h"

  #import <zlib.h>
  #import <CommonCrypto/CommonCrypto.h>
    #include <sys/wait.h>
    /* WEXITSTATUS is a function-like C macro, not importable in Swift; redefine as static inline */
    #ifdef WEXITSTATUS
    #undef WEXITSTATUS
    #endif
    static inline int32_t WEXITSTATUS(int x) { return (x >> 8) & 0xff; }
    #include <libproc.h>
  #include <notify.h>
    #include <sys/ptrace.h>

  long findcachedataoff(const char *mgkey);
  void LaraClearIconCache(void);

  @interface UIDevice(Private)
  + (BOOL)_hasHomeButton;
  @end

  void test(NSString *path);

  NS_ASSUME_NONNULL_BEGIN

  @interface VarCleanBridge : NSObject

  + (NSDictionary *)loadRulesNamed:(NSString *)resourceName
                          inBundle:(NSBundle *)bundle
                             error:(NSError * _Nullable * _Nullable)error;

  + (BOOL)probePathExists:(NSString *)path
              isDirectory:(BOOL *)isDirectory
                isSymlink:(BOOL *)isSymlink;

  @end

  NS_ASSUME_NONNULL_END
  