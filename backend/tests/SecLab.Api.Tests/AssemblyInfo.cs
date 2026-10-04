using Xunit;

// Every test host seeds the same SQL Server database at startup; running test classes in parallel
// races on a fresh database. Keep them sequential.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
