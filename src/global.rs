/// Print the output only for debug builds
/// Do not use in production as it leaks the secret data
pub trait DangerousDebugPrint {
    fn dangerous_debug(&self);
}
