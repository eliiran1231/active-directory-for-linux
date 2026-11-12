using Xunit;

// These are shared-directory integration tests. Several cases intentionally
// enumerate primary-group membership across the whole naming context while
// other cases create and delete principals, so parallel execution can observe
// an object between search and materialization.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
