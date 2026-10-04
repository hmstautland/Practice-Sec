using Xunit;

// The test hosts are configured through environment variables (EnvScope), which are process-wide:
// test classes must not run in parallel or one class's settings leak into the other's hosts.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
