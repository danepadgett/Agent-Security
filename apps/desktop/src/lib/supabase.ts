import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

if (!supabaseUrl || !supabaseAnonKey) {
  console.warn(
    "[hound] Supabase env vars missing — auth features disabled.",
    { url: supabaseUrl ? "present" : "MISSING", key: supabaseAnonKey ? "present" : "MISSING" },
  );
}

// Use placeholder values when not configured so the client can be imported
// without crashing the app — auth calls will fail gracefully at call time.
export const supabase = createClient(
  supabaseUrl ?? "https://placeholder.supabase.co",
  supabaseAnonKey ?? "placeholder",
);
