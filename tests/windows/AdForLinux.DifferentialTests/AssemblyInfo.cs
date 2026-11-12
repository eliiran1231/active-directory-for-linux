using Xunit;

// Every differential test talks to and often mutates the same live AD lab.
// Serial execution prevents concurrent ADSI/LDAP fixture setup from producing
// intermittent "local error" and "server could not be contacted" failures.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
