//! Process management syscalls
use crate::mm::{translated_byte_buffer, translated_ref, PageTable, VirtAddr};
use crate::task::{
    change_program_brk, exit_current_and_run_next, mmap, munmap, suspend_current_and_run_next,
};
use crate::task::current_user_token;
use crate::timer::get_time_us;
use core::mem::size_of;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let time_us = get_time_us();
    let time_val = TimeVal {
        sec: time_us / 1_000_000,
        usec: time_us % 1_000_000,
    };
    let time_val_ptr = &time_val as *const TimeVal as *const u8;
    let time_val_bytes = unsafe { core::slice::from_raw_parts(time_val_ptr, size_of::<TimeVal>()) };
    let buffers = translated_byte_buffer(current_user_token(), ts as *const u8, size_of::<TimeVal>());
    let mut offset = 0;
    for buffer in buffers {
        let len = buffer.len();
        buffer.copy_from_slice(&time_val_bytes[offset..offset + len]);
        offset += len;
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match trace_request {
        0 => {
            // Read: id is the address to read from
            if let Some(byte) = translated_ref(current_user_token(), id as *const u8) {
                *byte as isize
            } else {
                return -1;
            }
        }
        1 => {
            // Write: id is the address to write to, data is the byte value
            let user_token = current_user_token();
            let va = VirtAddr::from(id);
            if let Some(pte) = PageTable::from_token(user_token).translate(va.floor()) {
                if !pte.writable() {
                    return -1;
                }
            } else {
                return -1;
            }
            if let Some(byte) = translated_ref(user_token, id as *mut u8 as *const u8) {
                *byte = data as u8;
                0
            } else {
                -1
            }
        }
        2 => {
            // Syscall count query: id is the syscall number
            if let Some(count) = crate::task::get_syscall_count(id) {
                count as isize
            } else {
                -1
            }
        }
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if mmap(start, len, port) {
        0
    } else {
        -1
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if munmap(start, len) {
        0
    } else {
        -1
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
