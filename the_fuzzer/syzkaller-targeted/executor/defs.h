// AUTOGENERATED FILE

struct call_attrs_t { 
	uint64_t disabled;
	uint64_t timeout;
	uint64_t prog_timeout;
	uint64_t ignore_return;
	uint64_t breaks_returns;
};

struct call_props_t { 
	int fail_nth;
};

#define read_call_props_t(var, reader) { \
	(var).fail_nth = (int)(reader); \
}


#if GOOS_akaros
#define GOOS "akaros"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "361c8bb8e04aa58189bcdd153dc08078d629c0b5"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_darwin
#define GOOS "darwin"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "779b6eba5ed2afe2be20e54933945f0c690f44c4"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 8589934592
#endif

#endif

#if GOOS_freebsd
#define GOOS "freebsd"

#if GOARCH_386
#define GOARCH "386"
#define SYZ_REVISION "da8feb379744271d18d64d1cf4c6fcb5bd706c82"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 268435456
#endif

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "6dc4c93bc53316fd53fbccca758f17aca5aa4bac"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_fuchsia
#define GOOS "fuchsia"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "39b49347fadeff7b0bccd0f43900214f60b32bdc"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm64
#define GOARCH "arm64"
#define SYZ_REVISION "842a0bd6fc980569fa3f390af1c39c0b7e674fdc"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_linux
#define GOOS "linux"

#if GOARCH_386
#define GOARCH "386"
#define SYZ_REVISION "fcd0268665d5293b16c870b2f98ec795d727c5ce"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "f823f975287ef2ae3dc381d9e9b0e3bd3e9ceb06"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm
#define GOARCH "arm"
#define SYZ_REVISION "9fe37aba6f886de3ea0a0a8bb6eb0c356ada6490"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_arm64
#define GOARCH "arm64"
#define SYZ_REVISION "346bbbd80ad59186bd32887d25647b1701472897"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_mips64le
#define GOARCH "mips64le"
#define SYZ_REVISION "b399aaa28620875f3fcd04b559b64361c25397d8"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_ppc64le
#define GOARCH "ppc64le"
#define SYZ_REVISION "e1c54f6d76fda1c965e943be33e6fb24635d1796"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 65536
#define SYZ_NUM_PAGES 256
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_riscv64
#define GOARCH "riscv64"
#define SYZ_REVISION "74c9a666e818abe31d40d25cbb1350db78193666"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_s390x
#define GOARCH "s390x"
#define SYZ_REVISION "1c1f926013855d2f1dfccc0d8d1589dbd2958022"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 4294963200
#endif

#endif

#if GOOS_netbsd
#define GOOS "netbsd"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "cb2365d65813e006774f4b699735428b0823ab35"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_openbsd
#define GOOS "openbsd"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "a177a93234ea325582ce5e8c74b0328e94a627e1"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_test
#define GOOS "test"

#if GOARCH_32_fork_shmem
#define GOARCH "32_fork_shmem"
#define SYZ_REVISION "56f1ba1cd62f96652d12cada6ee07727ecec8a77"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_32_shmem
#define GOARCH "32_shmem"
#define SYZ_REVISION "28b679c2e1497afba9ee6e4e9dc9786d2c3a1cfd"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 1
#define SYZ_PAGE_SIZE 8192
#define SYZ_NUM_PAGES 2048
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_64
#define GOARCH "64"
#define SYZ_REVISION "8f25fd126819c3fb7a11fcfdb7c91c34d1551212"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#if GOARCH_64_fork
#define GOARCH "64_fork"
#define SYZ_REVISION "92e94349e0c54a9b21a3118bba20fa5e388764b7"
#define SYZ_EXECUTOR_USES_FORK_SERVER 1
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 8192
#define SYZ_NUM_PAGES 2048
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_trusty
#define GOOS "trusty"

#if GOARCH_arm
#define GOARCH "arm"
#define SYZ_REVISION "f2680480e24dd09e2cad256cc4219c3209cbf075"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

#if GOOS_windows
#define GOOS "windows"

#if GOARCH_amd64
#define GOARCH "amd64"
#define SYZ_REVISION "8967babc353ed00daaa6992068d3044bad9d29fa"
#define SYZ_EXECUTOR_USES_FORK_SERVER 0
#define SYZ_EXECUTOR_USES_SHMEM 0
#define SYZ_PAGE_SIZE 4096
#define SYZ_NUM_PAGES 4096
#define SYZ_DATA_OFFSET 536870912
#endif

#endif

