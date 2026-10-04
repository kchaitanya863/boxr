// boxr-vz: Native Apple Virtualization.framework Container Micro-VM Runner
//
// Replaces Docker daemon on macOS with a direct, ultra-fast, zero-overhead
// hypervisor micro-VM using Apple's native Virtualization.framework and virtio-fs.

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>
#include <signal.h>
#include <unistd.h>

static VZVirtualMachine *g_vm = nil;
static NSString *g_bundlePath = nil;

static void clean_exit_handler(void) {
    if (g_vm && [g_vm canStop]) {
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [g_vm stopWithCompletionHandler:^(NSError * _Nullable error) {
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
    }
}

@interface BoxrVMDelegate : NSObject <VZVirtualMachineDelegate>
@property (nonatomic, assign) BOOL finished;
@property (nonatomic, assign) int exitCode;
@end

@implementation BoxrVMDelegate
- (void)guestDidStopVirtualMachine:(VZVirtualMachine *)virtualMachine {
    self.finished = YES;
    CFRunLoopStop(CFRunLoopGetMain());
}

- (void)virtualMachine:(VZVirtualMachine *)virtualMachine didStopWithError:(NSError *)error {
    self.finished = YES;
    CFRunLoopStop(CFRunLoopGetMain());
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *bundlePath = nil;
        NSString *rootfsPath = nil;
        NSString *kernelPath = nil;
        NSString *initrdPath = nil;
        BOOL isDetach = NO;
        NSUInteger cpuCount = 2;
        unsigned long long memoryBytes = 2048 * 1024 * 1024ULL;

        NSMutableArray<NSString *> *mountSpecs = [NSMutableArray array];
        NSMutableArray<NSString *> *portSpecs = [NSMutableArray array];

        for (int i = 1; i < argc; i++) {
            NSString *arg = [NSString stringWithUTF8String:argv[i]];
            if ([arg isEqualToString:@"--bundle"] && i + 1 < argc) {
                bundlePath = [NSString stringWithUTF8String:argv[++i]];
            } else if ([arg isEqualToString:@"--rootfs"] && i + 1 < argc) {
                rootfsPath = [NSString stringWithUTF8String:argv[++i]];
            } else if ([arg isEqualToString:@"--mount"] && i + 1 < argc) {
                [mountSpecs addObject:[NSString stringWithUTF8String:argv[++i]]];
            } else if ([arg isEqualToString:@"--port"] && i + 1 < argc) {
                [portSpecs addObject:[NSString stringWithUTF8String:argv[++i]]];
            } else if ([arg isEqualToString:@"--kernel"] && i + 1 < argc) {
                kernelPath = [NSString stringWithUTF8String:argv[++i]];
            } else if ([arg isEqualToString:@"--initrd"] && i + 1 < argc) {
                initrdPath = [NSString stringWithUTF8String:argv[++i]];
            } else if ([arg isEqualToString:@"--detach"]) {
                isDetach = YES;
            } else if ([arg isEqualToString:@"--cpus"] && i + 1 < argc) {
                cpuCount = (NSUInteger)atoi(argv[++i]);
            } else if ([arg isEqualToString:@"--memory"] && i + 1 < argc) {
                memoryBytes = (unsigned long long)atoll(argv[++i]);
            }
        }

        if (!rootfsPath) {
            fprintf(stderr, "Error: --rootfs is required for boxr-vz\n");
            return 1;
        }

        NSString *homeDir = NSHomeDirectory();
        if (!kernelPath) {
            kernelPath = [homeDir stringByAppendingPathComponent:@".boxr/vm/vmlinux"];
        }
        if (!initrdPath) {
            initrdPath = [homeDir stringByAppendingPathComponent:@".boxr/vm/initrd.cpio.gz"];
        }

        if (![[NSFileManager defaultManager] fileExistsAtPath:kernelPath]) {
            fprintf(stderr, "Error: Linux kernel not found at %s\n", [kernelPath UTF8String]);
            return 1;
        }

        if (![[NSFileManager defaultManager] fileExistsAtPath:initrdPath]) {
            fprintf(stderr, "Error: Micro-VM initrd not found at %s\n", [initrdPath UTF8String]);
            return 1;
        }

        atexit(clean_exit_handler);

        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);

        void (^stopAndExit)(int) = ^(int sig) {
            if (g_vm && [g_vm canStop]) {
                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                [g_vm stopWithCompletionHandler:^(NSError * _Nullable errorOrNil) {
                    dispatch_semaphore_signal(sem);
                }];
                dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
            }
            if (bundlePath) {
                NSString *pidFile = [bundlePath stringByAppendingPathComponent:@"vm.pid"];
                [[NSFileManager defaultManager] removeItemAtPath:pidFile error:nil];
            }
            exit(128 + sig);
        };

        dispatch_source_t sigtermSrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
        dispatch_source_set_event_handler(sigtermSrc, ^{
            stopAndExit(SIGTERM);
        });
        dispatch_resume(sigtermSrc);

        dispatch_source_t sigintSrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0));
        dispatch_source_set_event_handler(sigintSrc, ^{
            stopAndExit(SIGINT);
        });
        dispatch_resume(sigintSrc);

        // Record PID if bundle path is provided
        if (bundlePath) {
            g_bundlePath = bundlePath;
            NSString *pidFile = [bundlePath stringByAppendingPathComponent:@"vm.pid"];
            NSString *pidStr = [NSString stringWithFormat:@"%d\n", getpid()];
            [pidStr writeToFile:pidFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }

        NSURL *kernelURL = [NSURL fileURLWithPath:kernelPath];
        NSURL *initrdURL = [NSURL fileURLWithPath:initrdPath];

        VZLinuxBootLoader *bootloader = [[VZLinuxBootLoader alloc] initWithKernelURL:kernelURL];
        bootloader.initialRamdiskURL = initrdURL;
        bootloader.commandLine = @"console=hvc0 quiet loglevel=3 random.trust_cpu=on random.trust_bootloader=on panic=1 root=boxr_rootfs rootfstype=virtiofs rootflags=rw init=/boxr-run.sh";

        VZVirtualMachineConfiguration *config = [[VZVirtualMachineConfiguration alloc] init];
        config.bootLoader = bootloader;
        config.CPUCount = cpuCount;
        config.memorySize = memoryBytes;

        NSMutableArray<VZVirtioFileSystemDeviceConfiguration *> *sharingDevices = [NSMutableArray array];

        // virtio-fs share for container rootfs
        VZSharedDirectory *dir = [[VZSharedDirectory alloc] initWithURL:[NSURL fileURLWithPath:rootfsPath] readOnly:NO];
        VZSingleDirectoryShare *share = [[VZSingleDirectoryShare alloc] initWithDirectory:dir];
        VZVirtioFileSystemDeviceConfiguration *fsConfig = [[VZVirtioFileSystemDeviceConfiguration alloc] initWithTag:@"boxr_rootfs"];
        fsConfig.share = share;
        [sharingDevices addObject:fsConfig];

        // Additional directory mounts
        for (NSString *mSpec in mountSpecs) {
            NSArray *parts = [mSpec componentsSeparatedByString:@"="];
            if ([parts count] == 2) {
                NSString *tag = parts[0];
                NSString *mPath = parts[1];
                if ([[NSFileManager defaultManager] fileExistsAtPath:mPath]) {
                    VZSharedDirectory *mDir = [[VZSharedDirectory alloc] initWithURL:[NSURL fileURLWithPath:mPath] readOnly:NO];
                    VZSingleDirectoryShare *mShare = [[VZSingleDirectoryShare alloc] initWithDirectory:mDir];
                    VZVirtioFileSystemDeviceConfiguration *mFsConfig = [[VZVirtioFileSystemDeviceConfiguration alloc] initWithTag:tag];
                    mFsConfig.share = mShare;
                    [sharingDevices addObject:mFsConfig];
                }
            }
        }
        config.directorySharingDevices = sharingDevices;

        // NAT networking for container outbound traffic
        VZVirtioNetworkDeviceConfiguration *netConfig = [[VZVirtioNetworkDeviceConfiguration alloc] init];
        netConfig.attachment = [[VZNATNetworkDeviceAttachment alloc] init];
        config.networkDevices = @[netConfig];

        // Virtio Entropy (RNG) device for instant /dev/urandom and getrandom entropy
        VZVirtioEntropyDeviceConfiguration *entropyConfig = [[VZVirtioEntropyDeviceConfiguration alloc] init];
        config.entropyDevices = @[entropyConfig];

        // Serial console
        VZVirtioConsoleDeviceSerialPortConfiguration *consoleConfig = [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
        NSPipe *dummyInPipe = [NSPipe pipe];
        NSFileHandle *readHandle = [NSFileHandle fileHandleWithStandardInput];
        NSFileHandle *writeHandle = [NSFileHandle fileHandleWithStandardOutput];

        if (isDetach && bundlePath) {
            NSString *logFile = [bundlePath stringByAppendingPathComponent:@"logs.txt"];
            [[NSFileManager defaultManager] createFileAtPath:logFile contents:nil attributes:nil];
            writeHandle = [NSFileHandle fileHandleForWritingAtPath:logFile];
            readHandle = [dummyInPipe fileHandleForReading];
        }

        VZFileHandleSerialPortAttachment *attachment = [[VZFileHandleSerialPortAttachment alloc] 
            initWithFileHandleForReading:readHandle 
            fileHandleForWriting:writeHandle];
        consoleConfig.attachment = attachment;
        config.serialPorts = @[consoleConfig];

        NSError *validateError = nil;
        if (![config validateWithError:&validateError]) {
            fprintf(stderr, "Error: Invalid VM configuration: %s\n", [[validateError localizedDescription] UTF8String]);
            return 1;
        }

        VZVirtualMachine *vm = [[VZVirtualMachine alloc] initWithConfiguration:config];
        g_vm = vm;

        BoxrVMDelegate *delegate = [[BoxrVMDelegate alloc] init];
        vm.delegate = delegate;

        dispatch_semaphore_t startSem = dispatch_semaphore_create(0);
        __block NSError *startError = nil;

        [vm startWithCompletionHandler:^(NSError * _Nullable errorIfFailed) {
            startError = errorIfFailed;
            dispatch_semaphore_signal(startSem);
        }];

        // Pump runloop while waiting for VM to start
        while (dispatch_semaphore_wait(startSem, DISPATCH_TIME_NOW) != 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }

        if (startError) {
            fprintf(stderr, "Error: Failed to start VM: %s\n", [[startError localizedDescription] UTF8String]);
            return 1;
        }

        // Published ports are forwarded by the host-side `__internal-port-forward`
        // daemon via Unix sockets in the virtio-fs shared bundle directory.
        // Guest relays are started in boxr-run.sh.

        // Run until guest powers down
        CFRunLoopRun();

        // Ensure VM is stopped cleanly if not already stopped
        if (vm.canStop) {
            dispatch_semaphore_t stopSem = dispatch_semaphore_create(0);
            [vm stopWithCompletionHandler:^(NSError * _Nullable error) {
                dispatch_semaphore_signal(stopSem);
            }];
            dispatch_semaphore_wait(stopSem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
        }

        if (isDetach && writeHandle) {
            @try {
                [writeHandle synchronizeFile];
                [writeHandle closeFile];
            } @catch (NSException *e) {}
        }

        // Read container exit code from rootfs
        int exitCode = 0;
        NSString *exitCodePath = [rootfsPath stringByAppendingPathComponent:@"boxr-exitcode"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:exitCodePath]) {
            NSString *content = [NSString stringWithContentsOfFile:exitCodePath encoding:NSUTF8StringEncoding error:nil];
            if (content) {
                exitCode = [content intValue];
            }
            [[NSFileManager defaultManager] removeItemAtPath:exitCodePath error:nil];
        }

        // Clean up runner script
        NSString *runScriptPath = [rootfsPath stringByAppendingPathComponent:@"boxr-run.sh"];
        [[NSFileManager defaultManager] removeItemAtPath:runScriptPath error:nil];

        // Clean up PID file
        if (bundlePath) {
            NSString *pidFile = [bundlePath stringByAppendingPathComponent:@"vm.pid"];
            [[NSFileManager defaultManager] removeItemAtPath:pidFile error:nil];
        }

        return exitCode;
    }
}
