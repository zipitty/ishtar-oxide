use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, bail};
#[cfg(target_os = "linux")]
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
};
#[cfg(target_os = "linux")]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, convert::TryInto};

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub address_space_bytes: u64,
    pub cpu_seconds: u64,
}

pub fn close_inherited_descriptors() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range has no memory-safety preconditions.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
            bail!("close_range failed: {}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    for fd in 3..256 {
        // SAFETY: closing an invalid descriptor is harmless.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply(policy: Policy) -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        );
    }
    set_limit(libc::RLIMIT_AS, policy.address_space_bytes)?;
    set_limit(libc::RLIMIT_CPU, policy.cpu_seconds)?;
    set_limit(libc::RLIMIT_NOFILE, 3)?;
    set_limit(libc::RLIMIT_NPROC, 1)?;
    set_limit(libc::RLIMIT_FSIZE, 0)?;
    apply_landlock()?;
    apply_seccomp()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply(policy: Policy) -> Result<()> {
    let _ = (policy.address_space_bytes, policy.cpu_seconds);
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        bail!("setrlimit failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock() -> Result<()> {
    let abi = ABI::V3;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .set_compatibility(CompatLevel::HardRequirement)
        .create()?
        .restrict_self()?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        bail!("Landlock was not fully enforced");
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
            .context("unsupported seccomp architecture")?,
    )?
    .try_into()
    .context("compile seccomp BPF")?;
    seccompiler::apply_filter(&filter).context("install seccomp filter")?;
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
