import { createClient as original } from '@supabase/supabase-js'
import { createClient } from '@dilion-io/auth-js'
import { AuthClient } from '@dilion-io/auth-js/auth'
import { AuthClient as OriginalAuth } from '@supabase/auth-js'
const factory: typeof original = createClient
const constructor: typeof OriginalAuth = AuthClient
void factory
void constructor
