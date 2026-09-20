-- Test databases used by the per-domain integration test suites (see Makefile).
CREATE DATABASE dilion_test_a;
CREATE DATABASE dilion_test_b;
CREATE DATABASE dilion_test_c;
CREATE DATABASE dilion_test_d;
-- The two isolated instances of the root multi-instance suite
-- (instances_db_test.go): a server serving both must keep them apart.
CREATE DATABASE dilion_test_h1;
CREATE DATABASE dilion_test_h2;
