use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, bail};
#[cfg(target_os = "linux")]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, convert::TryInto};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub address_space_bytes: u64,
    pub cpu_seconds: u64,
    pub open_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    pub no_new_privs_applied: bool,
    pub rlimits_applied: bool,
    pub seccomp_applied: bool,
    pub landlock_applied: bool,
    pub notes: Vec<String>,
}

#[cfg(target_os = "linux")]
pub fn apply_runner_sandbox(policy: &SandboxPolicy) -> Result<SandboxStatus> {
    set_no_new_privs()?;
    apply_rlimits(policy)?;
    apply_seccomp()?;
    Ok(SandboxStatus {
        no_new_privs_applied: true,
        rlimits_applied: true,
        seccomp_applied: true,
        landlock_applied: false,
        notes: vec![
            "fail-closed seccomp allowlist installed before guest instantiation".into(),
            "Landlock ruleset not yet installed; container root remains read-only".into(),
        ],
    })
}

#[cfg(not(target_os = "linux"))]
pub fn apply_runner_sandbox(_: &SandboxPolicy) -> Result<SandboxStatus> {
    Ok(SandboxStatus {
        no_new_privs_applied: false,
        rlimits_applied: false,
        seccomp_applied: false,
        landlock_applied: false,
        notes: vec!["Linux process sandbox controls are unavailable on this host".into()],
    })
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl is called with the documented PR_SET_NO_NEW_PRIVS signature.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_rlimits(policy: &SandboxPolicy) -> Result<()> {
    set_limit(libc::RLIMIT_AS, policy.address_space_bytes)?;
    set_limit(libc::RLIMIT_CPU, policy.cpu_seconds)?;
    set_limit(libc::RLIMIT_NOFILE, policy.open_files)?;
    set_limit(libc::RLIMIT_NPROC, 1)?;
    set_limit(libc::RLIMIT_FSIZE, 0)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: limit points to a valid rlimit and resource is an RLIMIT_* constant.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        bail!("setrlimit failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_seccomp() -> Result<()> {
    let mut rules = BTreeMap::new();

    for syscall in [
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_mremap,
        libc::SYS_munmap,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.insert(syscall, vec![]);
    }

    rules.insert(
        libc::SYS_mmap,
        vec![SeccompRule::new(vec![
            masked_zero(2, libc::PROT_EXEC as u64)?,
            SeccompCondition::new(
                3,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(libc::MAP_ANONYMOUS as u64),
                libc::MAP_ANONYMOUS as u64,
            )?,
            // `fd` is a C `int`. Its upper 32 bits in seccomp_data are not part
            // of the syscall ABI and are not consistently sign-extended across
            // architectures, so compare the actual 32-bit value of `-1`.
            SeccompCondition::new(
                4,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                u32::MAX as u64,
            )?,
        ])?],
    );
    rules.insert(
        libc::SYS_mprotect,
        vec![SeccompRule::new(vec![masked_zero(
            2,
            libc::PROT_EXEC as u64,
        )?])?],
    );

    rules.insert(libc::SYS_write, vec![fd_rule(1)?, fd_rule(2)?]);
    rules.insert(libc::SYS_writev, vec![fd_rule(1)?, fd_rule(2)?]);

    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .context("unsupported seccomp target architecture")?,
    )
    .context("construct runner seccomp filter")?
    .try_into()
    .context("compile runner seccomp BPF")?;
    seccompiler::apply_filter(&filter).context("install runner seccomp filter")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn fd_rule(fd: u64) -> Result<SeccompRule> {
    Ok(SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        fd,
    )?])?)
}

#[cfg(target_os = "linux")]
fn masked_zero(argument: u8, mask: u64) -> Result<SeccompCondition> {
    Ok(SeccompCondition::new(
        argument,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(mask),
        0,
    )?)
}
