use crate::OutputLib::{Crypto, Ssl};
use crate::OutputLibType::{Dynamic, Static};
use cmake::Config;
use macho::{MachObject, SymTabType, SymTabTypeMask, SymbolTableEntry};
use std::collections::HashSet;
use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Error, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

// NOTE: this build script is adopted from quiche (https://github.com/cloudflare/quiche)

// Additional parameters for Android build of BoringSSL.
//
// Android NDK < 18 with GCC.
const CMAKE_PARAMS_ANDROID_NDK_OLD_GCC: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[("ANDROID_TOOLCHAIN_NAME", "aarch64-linux-android-4.9")],
    ),
    (
        "arm",
        &[("ANDROID_TOOLCHAIN_NAME", "arm-linux-androideabi-4.9")],
    ),
    (
        "x86",
        &[("ANDROID_TOOLCHAIN_NAME", "x86-linux-android-4.9")],
    ),
    (
        "x86_64",
        &[("ANDROID_TOOLCHAIN_NAME", "x86_64-linux-android-4.9")],
    ),
];

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

const CMAKE_PARAMS_IOS: &[(&str, &[(&str, &str)])] = &[
    (
        "aarch64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
        ],
    ),
    (
        "x86_64",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
        ],
    ),
];

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: https://github.com/alexcrichton/cmake-rs/issues/18
fn get_boringssl_platform_output_path() -> PathBuf {
    if cfg!(windows) {
        // Code under this branch should match the logic in cmake-rs
        let debug_env_var = env::var("DEBUG").expect("DEBUG variable not defined in env");

        let deb_info = match &debug_env_var[..] {
            "false" => false,
            "true" => true,
            unknown => panic!("Unknown DEBUG={} env var.", unknown),
        };

        let opt_env_var = env::var("OPT_LEVEL").expect("OPT_LEVEL variable not defined in env");

        let subdir = match &opt_env_var[..] {
            "0" => "Debug",
            "1" | "2" | "3" => {
                if deb_info {
                    "RelWithDebInfo"
                } else {
                    "Release"
                }
            }
            "s" | "z" => "MinSizeRel",
            unknown => panic!("Unknown OPT_LEVEL={} env var.", unknown),
        };

        PathBuf::from(subdir)
    } else {
        PathBuf::new()
    }
}

#[cfg(feature = "fips")]
const AWS_LC_PATH: &str = "deps/aws-lc-fips";
#[cfg(not(feature = "fips"))]
const AWS_LC_PATH: &str = "deps/aws-lc";

/// Returns a new cmake::Config for building BoringSSL.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config() -> Config {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let pwd = env::current_dir().unwrap();

    let mut boringssl_cmake = Config::new(AWS_LC_PATH);

    // Add platform-specific parameters.
    match os.as_ref() {
        "android" => {
            let cmake_params_android = if cfg!(feature = "ndk-old-gcc") {
                CMAKE_PARAMS_ANDROID_NDK_OLD_GCC
            } else {
                CMAKE_PARAMS_ANDROID_NDK
            };

            // We need ANDROID_NDK_HOME to be set properly.
            println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
            let android_ndk_home = env::var("ANDROID_NDK_HOME")
                .expect("Please set ANDROID_NDK_HOME for Android build");
            let android_ndk_home = Path::new(&android_ndk_home);
            for (android_arch, params) in cmake_params_android {
                if *android_arch == arch {
                    for (name, value) in *params {
                        eprintln!("android arch={} add {}={}", arch, name, value);
                        boringssl_cmake.define(name, value);
                    }
                }
            }
            let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
            let toolchain_file = toolchain_file.to_str().unwrap();
            eprintln!("android toolchain={}", toolchain_file);
            boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

            // 21 is the minimum level tested. You can give higher value.
            boringssl_cmake.define("ANDROID_NATIVE_API_LEVEL", "21");
            boringssl_cmake.define("ANDROID_STL", "c++_shared");

            boringssl_cmake
        }

        "ios" => {
            for (ios_arch, params) in CMAKE_PARAMS_IOS {
                if *ios_arch == arch {
                    for (name, value) in *params {
                        eprintln!("ios arch={} add {}={}", arch, name, value);
                        boringssl_cmake.define(name, value);
                    }
                }
            }

            // Bitcode is always on.
            let bitcode_cflag = "-fembed-bitcode";

            // Hack for Xcode 10.1.
            let target_cflag = if arch == "x86_64" {
                "-target x86_64-apple-ios-simulator"
            } else {
                ""
            };

            let cflag = format!("{} {}", bitcode_cflag, target_cflag);

            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);

            boringssl_cmake
        }

        _ => {
            // Configure BoringSSL for building on 32-bit non-windows platforms.
            if arch == "x86" && os != "windows" {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    pwd.join(AWS_LC_PATH)
                        .join("util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }

            boringssl_cmake
        }
    }
}

/// Verify that the toolchains match https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
/// See "Installation Instructions" under section 12.1.
// TODO: maybe this should also verify the Go and Ninja versions? But those haven't been an issue in practice ...
fn verify_fips_clang_version() -> (&'static str, &'static str) {
    fn version(tool: &str) -> String {
        let output = match Command::new(tool).arg("--version").output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("warning: missing {}, trying other compilers: {}", tool, e);
                // NOTE: hard-codes that the loop below checks the version
                return String::new();
            }
        };
        assert!(output.status.success());
        let output = std::str::from_utf8(&output.stdout).expect("invalid utf8 output");
        output.lines().next().expect("empty output").to_string()
    }

    const REQUIRED_CLANG_VERSION: &str = "7.0.1";
    for (cc, cxx) in [
        ("clang-7", "clang++-7"),
        ("clang", "clang++"),
        ("cc", "c++"),
    ] {
        let cc_version = version(cc);
        if cc_version.contains(REQUIRED_CLANG_VERSION) {
            assert!(
                version(cxx).contains(REQUIRED_CLANG_VERSION),
                "mismatched versions of cc and c++"
            );
            return (cc, cxx);
        } else if cc == "cc" {
            panic!(
                "unsupported clang version \"{}\": FIPS requires clang {}",
                cc_version, REQUIRED_CLANG_VERSION
            );
        } else if !cc_version.is_empty() {
            eprintln!(
                "warning: FIPS requires clang version {}, skipping incompatible version \"{}\"",
                REQUIRED_CLANG_VERSION, cc_version
            );
        }
    }
    unreachable!()
}

struct BuildConfig {
    link_from: Option<PathBuf>,
    prefix: bool,
    fips: bool,
    lib_type: OutputLibType,
}

impl BuildConfig {
    fn create() -> Self {
        let link_from = match env::var("AWS_LC_BIN_PATH") {
            Ok(path) => Some(PathBuf::from(path)),
            _ => None,
        };
        // Default to static build only on Mac
        let mut lib_type = if cfg!(target_os = "macos") {
            Static
        } else {
            Dynamic
        };
        let mut fips = false;
        let prefix = true;

        if cfg!(feature = "fips") {
            if cfg!(target_os = "macos") {
                panic!("FIPS is not currently supported on MacOS");
            }
            fips = true;
            lib_type = Dynamic;
        } else if cfg!(feature = "dynamic") {
            lib_type = Dynamic;
        } else if cfg!(feature = "static") {
            lib_type = Static;
        }

        BuildConfig {
            link_from,
            prefix,
            fips,
            lib_type,
        }
    }
}

fn prepare_cmake_build(
    build_fips: bool,
    lib_type: OutputLibType,
    build_prefix: Option<(&str, &Path)>,
) -> Config {
    if !Path::new(AWS_LC_PATH).join("CMakeLists.txt").exists() {
        println!("cargo:warning=fetching aws-lc git submodule");
        // fetch the boringssl submodule
        let status = Command::new("git")
            .args(&["submodule", "update", "--init", "--recursive", AWS_LC_PATH])
            .status();
        if !status.map_or(false, |status| status.success()) {
            panic!("failed to fetch submodule - consider running `git submodule update --init --recursive deps/boringssl` yourself");
        }
    }

    let mut cfg = get_boringssl_cmake_config();

    if build_fips {
        let (clang, clangxx) = verify_fips_clang_version();
        cfg.define("CMAKE_C_COMPILER", clang);
        cfg.define("CMAKE_CXX_COMPILER", clangxx);
        cfg.define("CMAKE_ASM_COMPILER", clang);
        cfg.define("FIPS", "1");
    }

    if let Dynamic = lib_type {
        cfg.define("BUILD_SHARED_LIBS", "TRUE");
    }
    if let Some((symbol_prefix, symbol_file_path)) = build_prefix {
        cfg.define("BORINGSSL_PREFIX", symbol_prefix);
        cfg.define(
            "BORINGSSL_PREFIX_SYMBOLS",
            symbol_file_path.display().to_string(),
        );
    }

    cfg
}

trait LinkerSymbol {
    fn is_public(&self, lib_type: OutputLibType) -> bool;
}

impl LinkerSymbol for SymbolTableEntry {
    fn is_public(&self, lib_type: OutputLibType) -> bool {
        (self.n_type & SymTabTypeMask::N_TYPE as u8) != SymTabType::N_UNDF as u8
            && (self.n_type & SymTabTypeMask::N_EXT as u8) != 0
            && (lib_type == Static || (self.n_type & SymTabTypeMask::N_PEXT as u8) == 0)
    }
}

fn parse_mach_o_object(
    bytes: &[u8],
    lib_type: OutputLibType,
    symbols: &mut HashSet<String>,
) -> Result<(), String> {
    let mobject = MachObject::parse(bytes).map_err(|_| "Unable to parse object file.")?;
    for symtab in mobject.symtab {
        for entry in symtab.entries {
            //println!("Symbol: {}", entry.symbol);
            if entry.is_public(lib_type) {
                if let Some("_") = entry.symbol.get(0..1) {
                    symbols.insert(String::from(entry.symbol.get(1..).unwrap()));
                } else {
                    // TODO: This should be an error once AWS-LC's "bignum" assembly code
                    // no longer generates such symbols
                    /*
                    return Err(format!(
                        "Unexpected symbol without underscore prefix: {}",
                        entry.symbol
                    ));
                    */
                }
            }
        }
    }

    Ok(())
}

fn parse_static_symbols(path: &PathBuf, symbols: &mut HashSet<String>) -> Result<(), String> {
    use ar::Archive;

    let mut archive = Archive::new(File::open(path).unwrap());
    while let Some(entry_result) = archive.next_entry() {
        let mut entry = entry_result.unwrap();
        entry.header().size();

        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer).unwrap();
        parse_mach_o_object(&buffer, Static, symbols)?;
    }
    Ok(())
}

fn write_symbol_file(path: &PathBuf, symbols: HashSet<String>) -> Result<usize, Error> {
    let mut counter = 0usize;
    let mut file = File::create(path)?;
    let mut symbol_list: Vec<String> = symbols.into_iter().collect();
    symbol_list.sort();
    for symbol in symbol_list {
        if !symbol.contains("bignum") {
            let _ = file.write(symbol.as_bytes())?;
            let _ = file.write("\n".as_bytes())?;
            counter += 1;
        }
    }
    Ok(counter)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLib {
    Crypto,
    Ssl,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLibType {
    Static,
    Dynamic,
}

impl OutputLibType {
    fn file_extension(&self) -> &str {
        match self {
            Static => "a",
            Dynamic => "so",
        }
    }
    fn rust_lib_type(&self) -> &str {
        match self {
            Static => "static",
            Dynamic => "dylib",
        }
    }
}

impl OutputLib {
    fn libname(&self) -> &str {
        match self {
            Crypto => "crypto",
            Ssl => "ssl",
        }
    }

    fn locate(&self, path: &Path, lib_type: OutputLibType) -> PathBuf {
        path.join(Path::new(&format!("build/{}", self.libname())))
            .join(get_boringssl_platform_output_path())
            .join(Path::new(&format!(
                "lib{}.{}",
                self.libname(),
                lib_type.file_extension()
            )))
    }
}

fn build_aws_lc(build_config: &BuildConfig) -> Result<PathBuf, String> {
    let mut cmake_cfg = prepare_cmake_build(build_config.fips, build_config.lib_type, None);

    cmake_cfg.build_target("clean").build();
    let mut output_dir = cmake_cfg.build_target("ssl").build();

    if build_config.prefix {
        let mut symbols = HashSet::new();

        let libcrypto_path = Crypto.locate(&output_dir, build_config.lib_type);
        parse_static_symbols(&libcrypto_path, &mut symbols)?;

        let symbol_path = output_dir.join(Path::new("symbols.txt"));
        write_symbol_file(&symbol_path, symbols).map_err(|err| err.to_string())?;

        cmake_cfg.build_target("clean").build();

        let mut cmake_cfg = prepare_cmake_build(
            build_config.fips,
            build_config.lib_type,
            Some((&prefix_string(), &symbol_path)),
        );
        output_dir = cmake_cfg.build_target("ssl").build();
    }

    Ok(output_dir)
}

//TODO:
const VERSION: &str = env!("CARGO_PKG_VERSION");
fn prefix_string() -> String {
    format!("aws_lc_{}", VERSION.to_string().replace('.', "_"))
}

fn prepare_clang_args(build_prefix: Option<(&str, &PathBuf)>) -> Vec<String> {
    let mut clang_args: Vec<String> = Vec::new();
    let include_path =
        env::var("AWS_LC_INCLUDE_PATH").unwrap_or_else(|_| format!("{}/include", AWS_LC_PATH));

    clang_args.push("-I".to_string());
    clang_args.push(include_path);
    if let Some((prefix, aws_lc_dir)) = build_prefix {
        clang_args.push(format!("-DBORINGSSL_PREFIX={}", prefix));
        clang_args.push("-I".to_string());
        clang_args.push(
            aws_lc_dir
                .join("build")
                .join("symbol_prefix_include")
                .display()
                .to_string(),
        );
    }

    clang_args
}

#[derive(Debug)]
struct SymbolCallback {
    prefix: String,
}

impl SymbolCallback {
    fn new() -> Self {
        SymbolCallback {
            prefix: format!("{}_", prefix_string()),
        }
    }
}

impl bindgen::callbacks::ParseCallbacks for SymbolCallback {
    fn link_name_override(&self, function_name: &str) -> Option<String> {
        let mut result = function_name.to_string();
        if result.starts_with(&self.prefix) {
            result = result.replace(&self.prefix, "");
            Some(result)
        } else {
            None
        }
    }
}

fn main() {
    let build_config = BuildConfig::create();

    println!("cargo:rerun-if-env-changed=AWS_LC_BIN_PATH");
    let aws_lc_dir = build_config
        .link_from
        .to_owned()
        .unwrap_or_else(|| build_aws_lc(&build_config).unwrap());

    let libcrypto_path = Crypto.locate(&aws_lc_dir, build_config.lib_type);
    let libssl_path = Ssl.locate(&aws_lc_dir, build_config.lib_type);
    println!(
        "cargo:rustc-link-search=native={}",
        libcrypto_path.parent().unwrap().display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        libssl_path.parent().unwrap().display()
    );
    println!(
        "cargo:rustc-link-lib={}=crypto",
        build_config.lib_type.rust_lib_type()
    );
    println!(
        "cargo:rustc-link-lib={}=ssl",
        build_config.lib_type.rust_lib_type()
    );

    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    //panic!("Stop here");
    println!("cargo:rerun-if-env-changed=AWS_LC_INCLUDE_PATH");
    let clang_args = if build_config.prefix {
        prepare_clang_args(Some((&prefix_string(), &aws_lc_dir)))
    } else {
        prepare_clang_args(None)
    };

    let mut builder = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .rustfmt_bindings(true)
        .clang_args(&clang_args)
        .header("wrapper.h");

    if build_config.prefix {
        builder = builder.parse_callbacks(Box::new(SymbolCallback::new()))
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
