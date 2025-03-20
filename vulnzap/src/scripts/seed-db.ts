/**
 * Database Setup Script for Supabase
 * 
 * Run this script to initialize the database schema for VulnZap
 * 
 * Usage:
 * npm run db:seed
 */

import { createClient } from '@supabase/supabase-js';
import { config } from '../config/config.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Initialize Supabase client with service role key to create schema
const supabase = createClient(
  config.supabase.url,
  config.supabase.serviceKey || '',
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

async function createSchema() {
  console.log('Creating schema for VulnZap...');

  try {
    // 1. Create users table extensions
    console.log('Setting up users table extensions...');
    
    // Enable RLS on users table
    await supabase.rpc('enable_row_level_security', { table_name: 'auth.users' });
    
    // Add custom columns to the auth.users table
    await supabase.rpc('set_query', {
      query: `
        ALTER TABLE auth.users 
        ADD COLUMN IF NOT EXISTS tier text DEFAULT 'free' NOT NULL,
        ADD COLUMN IF NOT EXISTS stripe_customer_id text,
        ADD COLUMN IF NOT EXISTS company text,
        ADD COLUMN IF NOT EXISTS website text;
      `
    });
    
    // Create policy for users table
    await supabase.rpc('set_query', {
      query: `
        CREATE POLICY IF NOT EXISTS "Users can view own data" 
        ON auth.users 
        FOR SELECT 
        USING (auth.uid() = id);
      `
    });

    // 2. Create subscriptions table
    console.log('Creating subscriptions table...');
    await supabase
      .from(config.tables.subscriptions)
      .delete()
      .neq('id', 0)
      .then(async () => {
        await supabase.rpc('set_query', {
          query: `
            CREATE TABLE IF NOT EXISTS ${config.tables.subscriptions} (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id uuid REFERENCES auth.users(id) NOT NULL,
              subscription_id text NOT NULL,
              customer_id text NOT NULL,
              status text NOT NULL,
              tier text NOT NULL,
              price_id text NOT NULL,
              current_period_end bigint NOT NULL,
              cancel_at_period_end boolean DEFAULT false,
              created_at timestamp with time zone DEFAULT now(),
              updated_at timestamp with time zone DEFAULT now()
            );
            
            -- Enable RLS
            ALTER TABLE ${config.tables.subscriptions} ENABLE ROW LEVEL SECURITY;
            
            -- Create policies
            CREATE POLICY IF NOT EXISTS "Users can view own subscriptions" 
            ON ${config.tables.subscriptions} 
            FOR SELECT 
            USING (auth.uid() = user_id);
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON ${config.tables.subscriptions}(user_id);
            CREATE INDEX IF NOT EXISTS idx_subscriptions_subscription_id ON ${config.tables.subscriptions}(subscription_id);
          `
        });
      });

    // 3. Create usage stats table
    console.log('Creating usage stats table...');
    await supabase
      .from(config.tables.usageStats)
      .delete()
      .neq('id', 0)
      .then(async () => {
        await supabase.rpc('set_query', {
          query: `
            CREATE TABLE IF NOT EXISTS ${config.tables.usageStats} (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id uuid REFERENCES auth.users(id) NOT NULL,
              date date NOT NULL,
              scans_count integer DEFAULT 0,
              batch_scans_count integer DEFAULT 0,
              created_at timestamp with time zone DEFAULT now(),
              updated_at timestamp with time zone DEFAULT now(),
              UNIQUE(user_id, date)
            );
            
            -- Enable RLS
            ALTER TABLE ${config.tables.usageStats} ENABLE ROW LEVEL SECURITY;
            
            -- Create policies
            CREATE POLICY IF NOT EXISTS "Users can view own usage stats" 
            ON ${config.tables.usageStats} 
            FOR SELECT 
            USING (auth.uid() = user_id);
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_usage_stats_user_id ON ${config.tables.usageStats}(user_id);
            CREATE INDEX IF NOT EXISTS idx_usage_stats_date ON ${config.tables.usageStats}(date);
          `
        });
      });

    // 4. Create API keys table
    console.log('Creating API keys table...');
    await supabase
      .from(config.tables.apiKeys)
      .delete()
      .neq('id', 0)
      .then(async () => {
        await supabase.rpc('set_query', {
          query: `
            CREATE TABLE IF NOT EXISTS ${config.tables.apiKeys} (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id uuid REFERENCES auth.users(id) NOT NULL,
              key_prefix text NOT NULL,
              key_hash text NOT NULL,
              description text,
              is_active boolean DEFAULT true,
              last_used timestamp with time zone,
              created_at timestamp with time zone DEFAULT now(),
              expires_at timestamp with time zone,
              UNIQUE(key_prefix)
            );
            
            -- Enable RLS
            ALTER TABLE ${config.tables.apiKeys} ENABLE ROW LEVEL SECURITY;
            
            -- Create policies
            CREATE POLICY IF NOT EXISTS "Users can view own API keys" 
            ON ${config.tables.apiKeys} 
            FOR SELECT 
            USING (auth.uid() = user_id);
            
            CREATE POLICY IF NOT EXISTS "Users can insert own API keys" 
            ON ${config.tables.apiKeys} 
            FOR INSERT 
            WITH CHECK (auth.uid() = user_id);
            
            CREATE POLICY IF NOT EXISTS "Users can update own API keys" 
            ON ${config.tables.apiKeys} 
            FOR UPDATE 
            USING (auth.uid() = user_id);
            
            CREATE POLICY IF NOT EXISTS "Users can delete own API keys" 
            ON ${config.tables.apiKeys} 
            FOR DELETE 
            USING (auth.uid() = user_id);
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON ${config.tables.apiKeys}(user_id);
            CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON ${config.tables.apiKeys}(key_prefix);
          `
        });
      });

    // 5. Create vulnerability scan history table
    console.log('Creating vulnerability scan history table...');
    await supabase
      .from(config.tables.vulnerabilityScanHistory)
      .delete()
      .neq('id', 0)
      .then(async () => {
        await supabase.rpc('set_query', {
          query: `
            CREATE TABLE IF NOT EXISTS ${config.tables.vulnerabilityScanHistory} (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id uuid REFERENCES auth.users(id) NOT NULL,
              ecosystem text NOT NULL,
              package_name text NOT NULL,
              package_version text NOT NULL,
              is_vulnerable boolean NOT NULL,
              scan_result jsonb,
              created_at timestamp with time zone DEFAULT now()
            );
            
            -- Enable RLS
            ALTER TABLE ${config.tables.vulnerabilityScanHistory} ENABLE ROW LEVEL SECURITY;
            
            -- Create policies
            CREATE POLICY IF NOT EXISTS "Users can view own scan history" 
            ON ${config.tables.vulnerabilityScanHistory} 
            FOR SELECT 
            USING (auth.uid() = user_id);
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON ${config.tables.vulnerabilityScanHistory}(user_id);
            CREATE INDEX IF NOT EXISTS idx_scan_history_package ON ${config.tables.vulnerabilityScanHistory}(ecosystem, package_name, package_version);
            CREATE INDEX IF NOT EXISTS idx_scan_history_date ON ${config.tables.vulnerabilityScanHistory}(created_at);
          `
        });
      });

    // 6. Create vulnerability database table
    console.log('Creating vulnerability database table...');
    await supabase
      .from(config.tables.vulnerabilityDatabase)
      .delete()
      .neq('id', 0)
      .then(async () => {
        await supabase.rpc('set_query', {
          query: `
            CREATE TABLE IF NOT EXISTS ${config.tables.vulnerabilityDatabase} (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              ecosystem text NOT NULL,
              package_name text NOT NULL,
              vulnerable_versions text NOT NULL,
              patched_versions text,
              severity text NOT NULL,
              title text NOT NULL,
              description text NOT NULL,
              cve_id text,
              source text,
              reference_urls jsonb,
              created_at timestamp with time zone DEFAULT now(),
              updated_at timestamp with time zone DEFAULT now(),
              UNIQUE(ecosystem, package_name, cve_id)
            );
            
            -- Enable RLS to allow public read access
            ALTER TABLE ${config.tables.vulnerabilityDatabase} ENABLE ROW LEVEL SECURITY;
            
            -- Create policies
            CREATE POLICY IF NOT EXISTS "Public read access to vulnerability database" 
            ON ${config.tables.vulnerabilityDatabase} 
            FOR SELECT 
            USING (true);
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_vuln_db_package ON ${config.tables.vulnerabilityDatabase}(ecosystem, package_name);
            CREATE INDEX IF NOT EXISTS idx_vuln_db_cve ON ${config.tables.vulnerabilityDatabase}(cve_id);
          `
        });
      });

    // 7. Create trigger functions for updating timestamps
    console.log('Creating trigger functions...');
    await supabase.rpc('set_query', {
      query: `
        -- Create function for updating 'updated_at' timestamps
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = now();
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        -- Create trigger for subscriptions table
        DROP TRIGGER IF EXISTS set_updated_at_subscriptions ON ${config.tables.subscriptions};
        CREATE TRIGGER set_updated_at_subscriptions
        BEFORE UPDATE ON ${config.tables.subscriptions}
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();

        -- Create trigger for usage_stats table
        DROP TRIGGER IF EXISTS set_updated_at_usage_stats ON ${config.tables.usageStats};
        CREATE TRIGGER set_updated_at_usage_stats
        BEFORE UPDATE ON ${config.tables.usageStats}
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();

        -- Create trigger for vulnerability_database table
        DROP TRIGGER IF EXISTS set_updated_at_vulnerability_database ON ${config.tables.vulnerabilityDatabase};
        CREATE TRIGGER set_updated_at_vulnerability_database
        BEFORE UPDATE ON ${config.tables.vulnerabilityDatabase}
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
      `
    });

    console.log('Database schema created successfully!');
  } catch (error) {
    console.error('Error creating schema:', error);
  }
}

// Run the script
createSchema().catch(console.error); 