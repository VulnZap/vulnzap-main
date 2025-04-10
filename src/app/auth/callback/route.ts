import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

export async function GET(request: Request) {
  // Get the URL from the request
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get('code');

  // If code is present in the URL, exchange it for a session
  if (code) {
    // Create a Supabase client
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    const supabase = createClient(supabaseUrl || '', supabaseAnonKey || '');

    try {
      // Exchange the code for a session
      await supabase.auth.exchangeCodeForSession(code);

      // Redirect to the dashboard
      return NextResponse.redirect(new URL('/dashboard', request.url));
    } catch (error) {
      console.error('Error exchanging code for session:', error);

      // Redirect to login with error
      return NextResponse.redirect(
        new URL(
          `/login?error=${encodeURIComponent('Authentication failed')}`,
          request.url
        )
      );
    }
  }

  // If no code is present, redirect to login
  return NextResponse.redirect(new URL('/login', request.url));
}
