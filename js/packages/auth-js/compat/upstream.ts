// Independent control group: failures here also occur WITHOUT Dilion.
import { createClient } from '@supabase/supabase-js'
import { AuthClient } from '@supabase/auth-js'
export type SupabaseFactory = typeof createClient
export type SupabaseAuth = InstanceType<typeof AuthClient>
