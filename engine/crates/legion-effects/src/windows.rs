#![cfg(windows)]

//! Windows process-tree backend.
//!
//! A suspended process is assigned to a kill-on-close job before its primary
//! thread is resumed.  The job handle is kept alive until output has drained,
//! so descendants cannot outlive an execution receipt.

use std::{
    collections::BTreeMap,
    ffi::c_void,
    mem::{size_of, zeroed},
    os::windows::io::{FromRawHandle, RawHandle},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT},
    System::{
        Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT},
        Pipes::CreatePipe,
        Threading::{
            AssignProcessToJobObject, CreateJobObjectW, CreateProcessW, GetExitCodeProcess,
            JobObjectExtendedLimitInformation, ResumeThread, SetInformationJobObject,
            TerminateJobObject, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED,
            CREATE_UNICODE_ENVIRONMENT, JOBOBJECT_BASIC_LIMIT_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
        },
    },
};

use crate::{
    error::EffectError,
    platform::{PlatformProcess, ProcessFuture, ProcessLaunch, ProcessOutput},
    receipt::ProcessTreeEvidence,
};

#[derive(Debug)]
struct Handle(HANDLE);

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    fn new(raw: HANDLE) -> Result<Self, EffectError> {
        if raw.is_null() {
            Err(last_error("invalid handle"))
        } else {
            Ok(Self(raw))
        }
    }
    fn raw(&self) -> HANDLE {
        self.0
    }
    fn into_raw(self) -> HANDLE {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn last_error(context: &str) -> EffectError {
    EffectError::SpawnFailed(format!("{context}: Win32 error {}", unsafe {
        GetLastError()
    }))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn quote_arg(value: &str) -> String {
    if !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c == '"') {
        return value.to_owned();
    }
    let mut result = String::from("\"");
    let mut slashes = 0usize;
    for byte in value.bytes() {
        if byte == b'\\' {
            slashes += 1;
            continue;
        }
        if byte == b'"' {
            result.extend(std::iter::repeat('\\').take(slashes * 2 + 1));
            result.push('"');
            slashes = 0;
            continue;
        }
        result.extend(std::iter::repeat('\\').take(slashes));
        result.push(byte as char);
        slashes = 0;
    }
    result.extend(std::iter::repeat('\\').take(slashes * 2));
    result.push('"');
    result
}

fn environment_block(environment: &BTreeMap<String, String>) -> Vec<u16> {
    let mut block = Vec::new();
    for (name, value) in environment {
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

struct ChildHandles {
    process: Handle,
    job: Option<Handle>,
    stdout: Handle,
    stderr: Handle,
    pid: u32,
}

fn configure_job() -> Result<Handle, EffectError> {
    let job = Handle::new(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        ..unsafe { zeroed() }
    };
    let ok = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &mut limits as *mut _ as *mut c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error("configure kill-on-close job"));
    }
    Ok(job)
}

fn spawn_child(launch: &ProcessLaunch) -> Result<ChildHandles, EffectError> {
    let mut attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut stdout_read_raw: HANDLE = null_mut();
    let mut stdout_write_raw: HANDLE = null_mut();
    if unsafe { CreatePipe(&mut stdout_read_raw, &mut stdout_write_raw, &mut attrs, 0) } == 0 {
        return Err(last_error("create stdout pipe"));
    }
    let stdout_read = Handle::new(stdout_read_raw)?;
    let stdout_write = Handle::new(stdout_write_raw)?;
    if unsafe { SetHandleInformation(stdout_read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_error("make stdout reader private"));
    }
    let mut stderr_read_raw: HANDLE = null_mut();
    let mut stderr_write_raw: HANDLE = null_mut();
    if unsafe { CreatePipe(&mut stderr_read_raw, &mut stderr_write_raw, &mut attrs, 0) } == 0 {
        return Err(last_error("create stderr pipe"));
    }
    let stderr_read = Handle::new(stderr_read_raw)?;
    let stderr_write = Handle::new(stderr_write_raw)?;
    if unsafe { SetHandleInformation(stderr_read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_error("make stderr reader private"));
    }
    let job = configure_job()?;
    let mut command = quote_arg(&launch.executable);
    for arg in &launch.args {
        command.push(' ');
        command.push_str(&quote_arg(arg));
    }
    let mut command = wide(&command);
    let executable = wide(&launch.executable);
    let cwd = wide(&launch.cwd);
    let mut environment = environment_block(&launch.environment);
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = stdout_write.raw();
    startup.hStdError = stderr_write.raw();
    startup.hStdInput = null_mut();
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            environment.as_mut_ptr() as *mut c_void,
            cwd.as_ptr(),
            &startup,
            &mut info,
        )
    };
    drop(stdout_write);
    drop(stderr_write);
    if created == 0 {
        return Err(last_error("create suspended process"));
    }
    let process = Handle::new(info.hProcess)?;
    let thread = Handle::new(info.hThread)?;
    if unsafe { AssignProcessToJobObject(job.raw(), process.raw()) } == 0 {
        unsafe {
            TerminateJobObject(job.raw(), 1);
        }
        return Err(last_error("assign process to job"));
    }
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        unsafe {
            TerminateJobObject(job.raw(), 1);
        }
        return Err(last_error("resume process"));
    }
    drop(thread);
    Ok(ChildHandles {
        process,
        job: Some(job),
        stdout: stdout_read,
        stderr: stderr_read,
        pid: info.dwProcessId,
    })
}

async fn read_limited(
    mut file: tokio::fs::File,
    limit: usize,
    limited: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    loop {
        if output.len() == limit {
            let mut probe = [0u8; 1];
            match file.read(&mut probe).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    limited.store(true, Ordering::Release);
                    notify.notify_one();
                    break;
                }
            }
        }
        let size = match file.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(size) => size,
        };
        let take = size.min(limit - output.len());
        output.extend_from_slice(&buffer[..take]);
        if take != size {
            limited.store(true, Ordering::Release);
            notify.notify_one();
            break;
        }
    }
    output
}

async fn wait_process(process: HANDLE) -> Result<Option<i32>, EffectError> {
    let process_value = process as usize;
    tokio::task::spawn_blocking(move || {
        let process = process_value as HANDLE;
        unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(process, u32::MAX);
        }
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
            return Err(last_error("read process exit code"));
        }
        Ok(Some(code as i32))
    })
    .await
    .map_err(|error| EffectError::Internal(error.to_string()))?
}

fn request_cooperative_stop(child: &ChildHandles) {
    // CTRL_BREAK is cooperative for the new process group.  Job termination
    // remains the bounded fallback when a target ignores the request.
    unsafe {
        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.pid);
    }
}

fn terminate_job(child: &mut ChildHandles) -> bool {
    let Some(job) = child.job.as_ref() else {
        return true;
    };
    let terminated = unsafe { TerminateJobObject(job.raw(), 1) } != 0;
    if !terminated {
        // Closing a KILL_ON_JOB_CLOSE handle is the final bounded cleanup
        // path, including when TerminateJobObject itself is unavailable.
        child.job.take();
    }
    terminated
}

fn as_file(handle: Handle) -> tokio::fs::File {
    let raw = handle.into_raw();
    let file = unsafe { std::fs::File::from_raw_handle(raw as RawHandle) };
    tokio::fs::File::from_std(file)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsProcess;

impl PlatformProcess for WindowsProcess {
    fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
        Box::pin(async move {
            let started_at_ms = now_ms();
            let child = spawn_child(&launch)?;
            let limited = Arc::new(AtomicBool::new(false));
            let limit_notify = Arc::new(tokio::sync::Notify::new());
            let stdout = tokio::spawn(read_limited(
                as_file(child.stdout),
                launch.stdout_limit,
                limited.clone(),
                limit_notify.clone(),
            ));
            let stderr = tokio::spawn(read_limited(
                as_file(child.stderr),
                launch.stderr_limit,
                limited.clone(),
                limit_notify.clone(),
            ));
            let mut wait = Box::pin(wait_process(child.process.raw()));
            let mut exit_code = None;
            let mut timed_out = false;
            let mut cancelled = false;
            let mut hard_killed = false;
            let mut tree_terminated = false;
            let termination = tokio::time::sleep(Duration::from_millis(launch.timeout_ms));
            tokio::pin!(termination);
            tokio::select! {
                result = &mut wait => {
                    exit_code = result?;
                    hard_killed = terminate_job(&mut child);
                    tree_terminated = true;
                }
                _ = &mut termination => {
                    timed_out = true;
                    request_cooperative_stop(&child);
                    if launch.termination_grace_ms > 0 { tokio::time::sleep(Duration::from_millis(launch.termination_grace_ms)).await; }
                    hard_killed = terminate_job(&mut child) || hard_killed;
                    tree_terminated = true;
                    exit_code = wait.await?;
                }
                _ = launch.cancellation.cancelled() => {
                    cancelled = true;
                    request_cooperative_stop(&child);
                    if launch.termination_grace_ms > 0 { tokio::time::sleep(Duration::from_millis(launch.termination_grace_ms)).await; }
                    hard_killed = terminate_job(&mut child) || hard_killed;
                    tree_terminated = true;
                    exit_code = wait.await?;
                }
                _ = limit_notify.notified() => {
                    request_cooperative_stop(&child);
                    if launch.termination_grace_ms > 0 { tokio::time::sleep(Duration::from_millis(launch.termination_grace_ms)).await; }
                    hard_killed = terminate_job(&mut child) || hard_killed;
                    tree_terminated = true;
                    exit_code = wait.await?;
                }
            }
            let stdout = stdout
                .await
                .map_err(|error| EffectError::Internal(error.to_string()))?;
            let stderr = stderr
                .await
                .map_err(|error| EffectError::Internal(error.to_string()))?;
            let output_limited = limited.load(Ordering::Acquire);
            Ok(ProcessOutput {
                stdout,
                stderr,
                exit_code,
                signal: None,
                timed_out,
                cancelled,
                output_limited,
                kill_succeeded: !timed_out && !cancelled && !output_limited || hard_killed,
                process_tree: ProcessTreeEvidence {
                    started: true,
                    terminated: tree_terminated,
                    hard_killed,
                    reaped: true,
                    detail: Some("windows job object".into()),
                },
                started_at_ms,
                completed_at_ms: now_ms(),
            })
        })
    }
}
