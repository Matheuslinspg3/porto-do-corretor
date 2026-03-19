import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

function getRequiredEnv(name: 'VITE_SUPABASE_URL' | 'VITE_SUPABASE_PUBLISHABLE_KEY') {
  const value = import.meta.env[name];

  if (!value) {
    throw new Error(`Missing required Supabase environment variable: ${name}`);
  }

  return value;
}

const SUPABASE_URL = getRequiredEnv('VITE_SUPABASE_URL');
const SUPABASE_PUBLISHABLE_KEY = getRequiredEnv('VITE_SUPABASE_PUBLISHABLE_KEY');

export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    storage: localStorage,
    persistSession: true,
    autoRefreshToken: true,
  },
});
